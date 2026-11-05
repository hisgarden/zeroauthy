package actionsrules_test

import (
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/mfarules"
)

// Plan 33b (§6.2, §8.1): the WebAuthn factor values the post-login API
// documents for challengeWith, challengeWithAny, enrollWith and enrollWithAny
// move from unavailable to supported. internal/actions/mfa.go reads the
// frozen lists from mfarules.ActionMember, so the flip is asserted there.
func TestWebAuthnFactorsSupported(t *testing.T) {
	for _, name := range []string{"api.authentication.challengeWith", "api.authentication.challengeWithAny", "api.authentication.enrollWith", "api.authentication.enrollWithAny"} {
		m := mfarules.ActionMember(name)
		if m.Name != name {
			t.Errorf("member %s missing", name)
			continue
		}
		for _, factor := range []string{"webauthn-roaming", "webauthn-platform"} {
			if !slices.Contains(m.AvailableFactors, factor) {
				t.Errorf("%s: %s not available: %v", name, factor, m.AvailableFactors)
			}
			if slices.Contains(m.UnavailableFactors, factor) {
				t.Errorf("%s: %s still unavailable: %v", name, factor, m.UnavailableFactors)
			}
		}
		if !slices.Contains(m.UnavailableFactors, "push-notification") {
			t.Errorf("%s: push-notification must stay unavailable: %v", name, m.UnavailableFactors)
		}
	}
	if m := mfarules.ActionMember("api.multifactor.enable"); !slices.Contains(m.AvailableFactors, "webauthn-roaming") || !slices.Contains(m.AvailableFactors, "webauthn-platform") {
		t.Errorf("api.multifactor.enable any/guardian must include the WebAuthn factors: %v", m.AvailableFactors)
	}
}
