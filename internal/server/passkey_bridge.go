package server

import (
	"encoding/json"
	"net/http"
)

// The native Passkey APIs (Plan 33b, D-0062): /passkey/register and
// /passkey/challenge are frozen in api/authentication.yaml by Task 1 and
// served by the OAuth handlers from Task 15. Until then the generated
// interface needs these adapters, which answer 501 so no caller mistakes
// the contract for a working endpoint.

func (a authAPI) PasskeyRegister(w http.ResponseWriter, r *http.Request) {
	passkeyUnavailable(w)
}

func (a authAPI) PasskeyChallenge(w http.ResponseWriter, r *http.Request) {
	passkeyUnavailable(w)
}

func passkeyUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "passkey_unavailable",
		"error_description": "The native Passkey APIs are not available yet.",
	})
}
