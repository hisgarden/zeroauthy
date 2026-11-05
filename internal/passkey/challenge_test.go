package passkey_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/passkey"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/webauthn/webauthntest"
	"github.com/zeroauthy/zeroauthy/internal/webauthnrules"
)

// deadline bounds how long the concurrency case waits; outcomes are
// asserted, never timings.
const deadline = 10 * time.Second

func TestIssueTakeSingleUse(t *testing.T) {
	e := newEnv(t)
	b := hosted(passkey.PurposePasskeyLogin, "")
	iss := e.issue(t, b)
	if len(iss.Challenge) != webauthnrules.Limits.ChallengeBytes || iss.ID == "" || iss.Session != "" {
		t.Fatalf("issued = %+v", iss)
	}
	ch, err := e.svc.Take(e.ctx, tid, iss.ID, b)
	if err != nil || !bytes.Equal(ch, iss.Challenge) {
		t.Fatalf("first take = %x, %v", ch, err)
	}
	if _, err := e.svc.Take(e.ctx, tid, iss.ID, b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("second take = %v, want ErrCeremony", err)
	}
	if _, err := e.svc.Take(e.ctx, tid, "never-issued", b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("unknown id = %v", err)
	}
	if _, err := e.svc.Take(e.ctx, "ten_other", e.issue(t, b).ID, b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("other tenant = %v", err)
	}

	// 20 concurrent takes of one challenge: exactly one gets it.
	iss = e.issue(t, b)
	const n = 20
	var wg sync.WaitGroup
	results := make([][]byte, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = e.svc.Take(e.ctx, tid, iss.ID, b)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	close(start)
	select {
	case <-done:
	case <-time.After(deadline):
		t.Fatalf("%d concurrent takes did not return within %s", n, deadline)
	}
	winners := 0
	for i := range n {
		switch {
		case errs[i] == nil:
			winners++
			if !bytes.Equal(results[i], iss.Challenge) {
				t.Fatalf("winner got %x", results[i])
			}
		case !errors.Is(errs[i], passkey.ErrCeremony):
			t.Fatalf("loser %d: %v", i, errs[i])
		}
	}
	if winners != 1 {
		t.Fatalf("%d winners, want exactly one", winners)
	}
}

func TestTakeBinding(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "u1")
	e.user(t, "u2")
	for _, base := range []passkey.Binding{hosted(passkey.PurposePasskeyRegister, u.UserID), native(passkey.PurposePasskeyRegister, u.UserID)} {
		mutations := map[string]func(b *passkey.Binding){
			"purpose": func(b *passkey.Binding) { b.Purpose = passkey.PurposePasskeyLogin },
			"rp_id":   func(b *passkey.Binding) { b.RPID = "login.example.com" },
			"origin":  func(b *passkey.Binding) { b.Origins = []string{"https://login.example.com"} },
			"extra origin": func(b *passkey.Binding) {
				b.Origins = append(append([]string(nil), b.Origins...), "https://evil.example")
			},
			"txn":          func(b *passkey.Binding) { b.TxnID += "x" },
			"cookie":       func(b *passkey.Binding) { b.CookieHash += "x" },
			"client":       func(b *passkey.Binding) { b.ClientID += "x" },
			"realm":        func(b *passkey.Binding) { b.Realm += "x" },
			"organization": func(b *passkey.Binding) { b.Organization += "x" },
			"user":         func(b *passkey.Binding) { b.UserID = "auth0|u2" },
		}
		for name, mutate := range mutations {
			iss := e.issue(t, base)
			want := base
			want.Origins = append([]string(nil), base.Origins...)
			mutate(&want)
			if _, err := e.svc.Take(e.ctx, tid, iss.ID, want); !errors.Is(err, passkey.ErrCeremony) {
				t.Fatalf("%s mismatch: %v", name, err)
			}
			// The mismatched take consumed the challenge.
			if _, err := e.svc.Take(e.ctx, tid, iss.ID, base); !errors.Is(err, passkey.ErrCeremony) {
				t.Fatalf("%s: challenge reusable after a mismatched take: %v", name, err)
			}
		}
	}

	// Expiry at ExpiresAt by the injected clock; the default hosted
	// lifetime is the frozen one.
	t0 := e.clock.Now()
	b := hosted(passkey.PurposePasskeyLogin, "")
	iss := e.issue(t, b)
	if !iss.ExpiresAt.Equal(t0.Add(webauthnrules.Limits.HostedChallengeTTL)) {
		t.Fatalf("hosted expiry = %v", iss.ExpiresAt)
	}
	edge := e.issue(t, b)
	e.clock.Set(iss.ExpiresAt.Add(-time.Nanosecond))
	if _, err := e.svc.Take(e.ctx, tid, edge.ID, b); err != nil {
		t.Fatalf("take just before expiry: %v", err)
	}
	e.clock.Set(iss.ExpiresAt)
	if _, err := e.svc.Take(e.ctx, tid, iss.ID, b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("take at ExpiresAt = %v", err)
	}
	e.clock.Set(t0)
	short, err := e.svc.Issue(e.ctx, tid, b, time.Minute)
	if err != nil || !short.ExpiresAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("explicit ttl: %+v, %v", short, err)
	}

	// A failed verification after Take leaves nothing reusable.
	auth := webauthntest.New(webauthntest.Options{})
	e.enroll(t, u, auth)
	b = hosted(passkey.PurposePasskeyLogin, "")
	iss = e.issue(t, b)
	raw := auth.Get(e.svc.RequestOptions(host, iss.Challenge, 0), "https://evil.example")
	ch := e.take(t, iss, b)
	if _, err := e.svc.Login(e.ctx, tid, raw, ch, b); !errors.Is(err, passkey.ErrCeremony) || reason(err) != "origin" {
		t.Fatalf("forged origin = %v (%s)", err, reason(err))
	}
	if _, err := e.svc.Take(e.ctx, tid, iss.ID, b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("challenge reusable after a failed verification: %v", err)
	}
	if _, err := e.st.MFA().GetChallenge(e.ctx, tid, iss.ID, e.clock.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("challenge row kept: %v", err)
	}

	// Malformed bindings are refused at issue.
	for name, bad := range map[string]passkey.Binding{
		"purpose":          {Purpose: "password", RPID: host, Origins: []string{origin}, TxnID: "t"},
		"rp_id":            {Purpose: passkey.PurposePasskeyLogin, Origins: []string{origin}, TxnID: "t"},
		"origins":          {Purpose: passkey.PurposePasskeyLogin, RPID: host, TxnID: "t"},
		"neither":          {Purpose: passkey.PurposePasskeyLogin, RPID: host, Origins: []string{origin}},
		"mfa without user": {Purpose: passkey.PurposeWebAuthnAssert, RPID: host, Origins: []string{origin}, TxnID: "t"},
	} {
		if _, err := e.svc.Issue(e.ctx, tid, bad, 0); err == nil {
			t.Fatalf("%s: malformed binding issued", name)
		}
	}
}

func TestNativeSessionHashed(t *testing.T) {
	e := newEnv(t)
	t0 := e.clock.Now()
	b := native(passkey.PurposePasskeyLogin, "")
	iss := e.issue(t, b)
	if iss.Session == "" || iss.ID != secrets.HashToken(iss.Session) || iss.ID == iss.Session {
		t.Fatalf("issued = %+v", iss)
	}
	if !iss.ExpiresAt.Equal(t0.Add(webauthnrules.Limits.NativeTimeout + webauthnrules.Limits.NativeGrace)) {
		t.Fatalf("native expiry = %v", iss.ExpiresAt)
	}
	if _, err := e.st.MFA().GetChallenge(e.ctx, tid, iss.Session, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row stored under the raw session: %v", err)
	}
	row, err := e.st.MFA().GetChallenge(e.ctx, tid, iss.ID, t0)
	if err != nil {
		t.Fatal(err)
	}
	dump, _ := json.Marshal(row)
	if strings.Contains(string(dump), iss.Session) || strings.Contains(string(row.Binding), iss.Session) {
		t.Fatalf("session stored: %s", dump)
	}
	if row.Kind != string(passkey.PurposePasskeyLogin) || row.UserID != "" || !bytes.Equal(row.Challenge, iss.Challenge) {
		t.Fatalf("row = %+v", row)
	}
	if _, err := e.svc.Take(e.ctx, tid, iss.Session, b); !errors.Is(err, passkey.ErrCeremony) {
		t.Fatalf("take by raw session = %v", err)
	}
	// The raw-session attempt above addressed no row, so the hashed ID
	// still works once.
	if ch := e.take(t, iss, b); !bytes.Equal(ch, iss.Challenge) {
		t.Fatal("challenge differs")
	}
	// Two sessions never collide.
	if other := e.issue(t, b); other.Session == iss.Session || other.ID == iss.ID {
		t.Fatal("sessions repeat")
	}
}
