// Package webauthnrules freezes the Plan 33b passkey and WebAuthn MFA wire
// contract: every documented rule with its public source URL, the hosted
// prompt, screen and text-key names, the log detail allowlists and the
// numeric limits later tasks read instead of literals. It contains no
// verifier, storage, ceremony or page runtime; see D-0062 for the local
// rulings LR33b-1…37, the controller calls K1–K14 and R1–R3 and the
// observe-later points W1–W12.
package webauthnrules

import (
	_ "embed"
	"encoding/json"
	"slices"
	"time"
)

// Rule is one documented behaviour with the public page it was derived from.
type Rule struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	Statement string `json:"statement"`
}

// Ceremony records the §4.5 parameters of one WebAuthn ceremony family.
type Ceremony struct {
	UserVerification        string `json:"userVerification"`
	ResidentKey             string `json:"residentKey"`
	AuthenticatorAttachment string `json:"authenticatorAttachment"`
	Credentials             string `json:"credentials"`
	UVEnforced              any    `json:"uv_enforced"`
}

// LimitSchema is the frozen numeric contract as stored in the inventory.
type LimitSchema struct {
	MaxPasskeys               int `json:"max_passkeys"`
	HostedChallengeTTLSeconds int `json:"hosted_challenge_ttl_seconds"`
	NativeTimeoutSeconds      int `json:"native_timeout_seconds"`
	NativeGraceSeconds        int `json:"native_grace_seconds"`
	ProgressiveSnoozeDays     int `json:"progressive_snooze_days"`
	LocalSnoozeDays           int `json:"local_snooze_days"`
	PlatformRemindDays        int `json:"platform_remind_days"`
	PlatformRefuseDays        int `json:"platform_refuse_days"`
	NicknameMin               int `json:"nickname_min"`
	NicknameMax               int `json:"nickname_max"`
	ChallengeBytes            int `json:"challenge_bytes"`
	UserHandleBytes           int `json:"user_handle_bytes"`
	AttestationMax            int `json:"attestation_max"`
	ClientDataMax             int `json:"client_data_max"`
	CredentialIDMax           int `json:"credential_id_max"`
	COSEMax                   int `json:"cose_max"`
	CBORDepth                 int `json:"cbor_depth"`
	CBORItems                 int `json:"cbor_items"`
	RPIDMax                   int `json:"rpid_max"`
}

// LimitSet is the typed view of LimitSchema that runtime packages consume.
// Durations are time.Duration so no caller multiplies seconds or days again.
type LimitSet struct {
	MaxPasskeys        int
	HostedChallengeTTL time.Duration
	NativeTimeout      time.Duration
	NativeGrace        time.Duration
	ProgressiveSnooze  time.Duration
	LocalSnooze        time.Duration
	PlatformRemind     time.Duration
	PlatformRefuse     time.Duration
	NicknameMin        int
	NicknameMax        int
	ChallengeBytes     int
	UserHandleBytes    int
	AttestationMax     int
	ClientDataMax      int
	CredentialIDMax    int
	COSEMax            int
	CBORDepth          int
	CBORItems          int
	RPIDMax            int
}

// Contract is the complete frozen inventory. Prose maps keep local decisions
// inspectable; the runtime tasks enforce and test them at their boundaries.
type Contract struct {
	Version           int                 `json:"version"`
	ReviewedAt        string              `json:"reviewed_at"`
	FetchedAt         string              `json:"fetched_at"`
	Decision          string              `json:"decision"`
	Evidence          map[string]string   `json:"evidence"`
	Rules             []Rule              `json:"rules"`
	Screens           map[string][]string `json:"screens"`
	Prompts           map[string]string   `json:"prompts"`
	HostedPaths       map[string]string   `json:"hosted_paths"`
	TextKeys          map[string][]string `json:"text_keys"`
	Ceremonies        map[string]Ceremony `json:"ceremonies"`
	PubKeyCredParams  []int64             `json:"pub_key_cred_params"`
	AssertionAlgs     []int64             `json:"assertion_algorithms"`
	Attestation       string              `json:"attestation"`
	DOMExceptionNames []string            `json:"dom_exception_names"`
	Native            map[string]any      `json:"native"`
	Management        map[string]any      `json:"management"`
	SessionMethods    []string            `json:"session_methods"`
	SnoozeKinds       []string            `json:"snooze_kinds"`
	ChallengeKinds    []string            `json:"challenge_kinds"`
	ScrubKeys         []string            `json:"scrub_keys"`
	LogDetails        map[string][]string `json:"log_details"`
	LogCodes          map[string]string   `json:"log_codes"`
	Limits            LimitSchema         `json:"limits"`
	Rulings           []string            `json:"rulings"`
	ControllerCalls   []string            `json:"controller_calls"`
	ObserveLater      []string            `json:"observe_later"`
	Spike             map[string]string   `json:"spike"`
}

//go:embed inventory.json
var inventoryJSON []byte

var frozen = Inventory()

// Limits are the frozen numeric rules (documented values or D-0062 local
// rulings). Every later task reads these instead of literals.
var Limits = limitsOf(frozen.Limits)

func limitsOf(l LimitSchema) LimitSet {
	day := 24 * time.Hour
	return LimitSet{
		MaxPasskeys:        l.MaxPasskeys,
		HostedChallengeTTL: time.Duration(l.HostedChallengeTTLSeconds) * time.Second,
		NativeTimeout:      time.Duration(l.NativeTimeoutSeconds) * time.Second,
		NativeGrace:        time.Duration(l.NativeGraceSeconds) * time.Second,
		ProgressiveSnooze:  time.Duration(l.ProgressiveSnoozeDays) * day,
		LocalSnooze:        time.Duration(l.LocalSnoozeDays) * day,
		PlatformRemind:     time.Duration(l.PlatformRemindDays) * day,
		PlatformRefuse:     time.Duration(l.PlatformRefuseDays) * day,
		NicknameMin:        l.NicknameMin,
		NicknameMax:        l.NicknameMax,
		ChallengeBytes:     l.ChallengeBytes,
		UserHandleBytes:    l.UserHandleBytes,
		AttestationMax:     l.AttestationMax,
		ClientDataMax:      l.ClientDataMax,
		CredentialIDMax:    l.CredentialIDMax,
		COSEMax:            l.COSEMax,
		CBORDepth:          l.CBORDepth,
		CBORItems:          l.CBORItems,
		RPIDMax:            l.RPIDMax,
	}
}

// Inventory returns a deep independent snapshot of the frozen contract.
func Inventory() Contract {
	var c Contract
	if err := json.Unmarshal(inventoryJSON, &c); err != nil {
		panic("webauthnrules: invalid inventory: " + err.Error())
	}
	return c
}

// Rules returns every frozen rule with its source URL.
func Rules() []Rule { return slices.Clone(frozen.Rules) }

// Screens maps a page family (the Auth0 prompt, or `mfa-webauthn` for every
// screen the WebAuthn MFA pages render, reset-password challenges included)
// to its screen names. Prompt gives a screen's documented prompt.
func Screens() map[string][]string {
	out := make(map[string][]string, len(frozen.Screens))
	for k, v := range frozen.Screens {
		out[k] = slices.Clone(v)
	}
	return out
}

// Prompt returns the documented Auth0 prompt of a screen, or "".
func Prompt(screen string) string { return frozen.Prompts[screen] }

// TextKeys returns the documented custom-text keys this plan adds to or
// renders on a screen (existing screens list only their passkey keys).
func TextKeys(screen string) []string { return slices.Clone(frozen.TextKeys[screen]) }

// LogDetails returns the `details` fields a Plan 33b emission of code may
// carry (§8.2); nil for codes this plan does not emit.
func LogDetails(code string) []string { return slices.Clone(frozen.LogDetails[code]) }

// LogCodes maps each code to the frozen Plan 33b emission rule.
func LogCodes() map[string]string {
	out := make(map[string]string, len(frozen.LogCodes))
	for k, v := range frozen.LogCodes {
		out[k] = v
	}
	return out
}

// Ceremonies returns the §4.5 ceremony parameters by family.
func Ceremonies() map[string]Ceremony {
	out := make(map[string]Ceremony, len(frozen.Ceremonies))
	for k, v := range frozen.Ceremonies {
		out[k] = v
	}
	return out
}

// ScrubKeys lists the JSON key names the log scrubber must hide.
func ScrubKeys() []string { return slices.Clone(frozen.ScrubKeys) }
