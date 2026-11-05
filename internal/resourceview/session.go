package resourceview

import "github.com/zeroauthy/zeroauthy/internal/store"

// SessionAuthentication is a session's authentication member in Auth0's
// shape (SessionAuthenticationSignals): the methods the login recorded
// (Plan 33b spec §5.4), each with its name, the MFA factor type for "mfa",
// and when it was completed. A session stored before methods were recorded
// keeps the earlier output, a single pwd at the authentication time.
func SessionAuthentication(s *store.LoginSession) map[string]any {
	methods := []map[string]any{}
	for _, m := range s.AuthMethods {
		at := m.At
		if at.IsZero() {
			at = s.AuthenticatedAt
		}
		v := map[string]any{"name": m.Name, "timestamp": userTime(at)}
		if m.Type != "" {
			v["type"] = m.Type
		}
		methods = append(methods, v)
	}
	if len(methods) == 0 {
		methods = append(methods, map[string]any{"name": "pwd", "timestamp": userTime(s.AuthenticatedAt)})
	}
	return map[string]any{"methods": methods}
}
