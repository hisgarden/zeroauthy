package passkey

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// Enrollment kinds the post-login prompt can offer (spec section 3.5).
const (
	PromptNone        = ""
	PromptProgressive = "progressive"
	PromptLocal       = "local"
)

// LoginContext is what the post-login prompt decision needs about the login
// that just completed: its first factor and, for a passkey login, the
// assertion's authenticator attachment (WebAuthn L3).
type LoginContext struct {
	// FirstFactor is the session's first authentication method name:
	// "pwd", "passkey", "federated", "email" or "sms".
	FirstFactor string
	// Attachment is the passkey assertion's authenticatorAttachment, empty
	// when the browser omitted it. Local enrollment is offered only for
	// "cross-platform" (Review Focus 5).
	Attachment string
	// PlatformAvailable is the page script's report that this browser has a
	// user-verifying platform authenticator.
	PlatformAvailable bool
	// DeviceScope is the hashed device cookie for local snoozes.
	DeviceScope string
}

// EnrollmentPrompt decides which post-login passkey enrollment to offer, or
// PromptNone. It runs after the login's MFA is satisfied and before consent
// (spec section 3.5): progressive after a password login with no passkey for
// the effective RP ID, local after a cross-device passkey login on a browser
// with a platform authenticator. Both honour the connection's options, the
// 20-passkey limit and the user's snoozes, and both need WebAuthn to work.
func (s *Service) EnrollmentPrompt(ctx context.Context, tid string, u *store.User, conn *store.Connection, res tenant.Resolved, in LoginContext) (string, error) {
	if u == nil || u.UserID == "" || u.Blocked {
		return PromptNone, nil
	}
	policy, rp, effective, err := s.Effective(ctx, tid, res, conn)
	if err != nil {
		return PromptNone, err
	}
	if !effective || !rp.Valid {
		return PromptNone, nil
	}
	now := s.now()

	switch in.FirstFactor {
	case "pwd":
		if !policy.Progressive {
			return PromptNone, nil
		}
		if snoozed(ctx, s, tid, u.UserID, store.SnoozePasskeyProgressive, rp.RPID, now) {
			return PromptNone, nil
		}
	case "passkey":
		if !policy.Local {
			return PromptNone, nil
		}
		// Review Focus 5: a browser that omits authenticatorAttachment, or
		// reports a platform authenticator already, gets no local prompt.
		if in.Attachment != "cross-platform" || !in.PlatformAvailable {
			return PromptNone, nil
		}
		if in.DeviceScope == "" {
			return PromptNone, nil
		}
		if snoozed(ctx, s, tid, u.UserID, store.SnoozePasskeyLocal, in.DeviceScope, now) {
			return PromptNone, nil
		}
	default:
		// A federated, email or sms first factor is never offered a prompt.
		return PromptNone, nil
	}

	list, err := s.st.MFA().ListAuthenticators(ctx, tid, u.UserID)
	if err != nil {
		return PromptNone, err
	}
	passkeys := 0
	hasForRP := false
	for i := range list {
		a := &list[i]
		if a.Type != "passkey" || !a.Confirmed {
			continue
		}
		passkeys++
		if a.RPID == rp.RPID {
			hasForRP = true
		}
	}
	// The 20-passkey limit and an existing passkey for this RP ID both end
	// the offer.
	if passkeys >= webauthnrules.Limits.MaxPasskeys {
		return PromptNone, nil
	}
	if in.FirstFactor == "pwd" {
		if hasForRP {
			return PromptNone, nil
		}
		return PromptProgressive, nil
	}
	// Local enrollment excludes the user's credentials for the RP ID, so an
	// existing one is fine; the device-local credential is what is new.
	return PromptLocal, nil
}

// snoozed reports whether the user has a live snooze of this kind and scope.
// A store without webauthn.v1 has no snoozes, which offers the prompt.
func snoozed(ctx context.Context, s *Service, tid, uid, kind, scope string, now time.Time) bool {
	_, err := s.st.WebAuthn().GetSnooze(ctx, tid, uid, kind, scope, now)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		return false
	}
	return true
}

// Snooze records that the user declined an enrollment prompt, until at the
// frozen window of its kind (LR33b-13, LR33b-14). A store without
// webauthn.v1 reports the capability error.
func (s *Service) Snooze(ctx context.Context, tid, uid, kind, scope string, from time.Time) error {
	var window time.Duration
	switch kind {
	case store.SnoozePasskeyProgressive, store.SnoozePasskeyLocal:
		window = webauthnrules.Limits.ProgressiveSnooze
	case store.SnoozePlatformRemind:
		window = webauthnrules.Limits.PlatformRemind
	case store.SnoozePlatformRefuse:
		window = webauthnrules.Limits.PlatformRefuse
	default:
		return store.ErrInvalid
	}
	if scope == "" {
		return store.ErrInvalid
	}
	return s.st.WebAuthn().PutSnooze(ctx, &store.WebAuthnSnooze{
		TenantID: tid, UserID: uid, Kind: kind, ScopeKey: scope, Until: from.Add(window),
	})
}

// DeviceScope is the hashed device cookie a local prompt binds to
// (LR33b-14): a stable, non-reversible per-browser key.
func DeviceScope(cookie string) string {
	if cookie == "" {
		return ""
	}
	return session.DeviceScope(cookie)
}
