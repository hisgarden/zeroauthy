package clientrules

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// FromClient and Apply are inverses, so an update that changes nothing
// leaves a client as it was.
func TestFromClientApplyRoundTrip(t *testing.T) {
	skip := true
	for _, c := range []*store.Client{
		{Name: "spa", AppType: store.AppTypeSPA, TokenEndpointAuthMethod: store.AuthMethodNone,
			GrantTypes: []string{GrantAuthorizationCode}, Callbacks: []string{"https://a.test/cb"},
			RefreshToken: store.RefreshTokenPolicy{Rotating: true, Expiring: true, Leeway: 3, TokenLifetime: 100, IdleTokenLifetime: 50},
			IsFirstParty: true, RedirectionPolicy: store.RedirectionPolicyAllowAlways},
		{Name: "tp", AppType: store.AppTypeRegularWeb, TokenEndpointAuthMethod: store.AuthMethodClientSecretBasic,
			IsFirstParty: false, ThirdPartySecurityMode: store.SecurityModePermissive, IDTokenLifetime: 600,
			RedirectionPolicy: store.RedirectionPolicyOpenRedirectProtection, SkipNonVerifiableCallbackURIConfirmationPrompt: &skip,
			RequirePushedAuthorizationRequests: true},
		{Name: "org", AppType: store.AppTypeRegularWeb, TokenEndpointAuthMethod: store.AuthMethodClientSecretPost, IsFirstParty: true,
			OrganizationUsage: store.OrgUsageRequire, OrganizationRequireBehavior: store.OrgBehaviorPreLoginPrompt,
			OrganizationDiscoveryMethods: []string{store.OrgDiscoveryEmail}},
	} {
		s := FromClient(c)
		got := &store.Client{}
		Apply(got, &s)
		if !reflect.DeepEqual(got, c) {
			t.Errorf("%s: round trip\n got %+v\nwant %+v", c.Name, got, c)
		}
	}
}

func TestNormalizeDefaultsAndRefusals(t *testing.T) {
	s := Spec{AppType: "native"}
	if errs := Normalize(&s, false); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s.TokenEndpointAuthMethod != store.AuthMethodNone || !*s.IsFirstParty || s.RedirectionPolicy != store.RedirectionPolicyAllowAlways ||
		s.RefreshToken.RotationType != NonRotating || s.RefreshToken.ExpirationType != NonExpiring {
		t.Fatalf("native defaults = %+v", s)
	}
	for name, tc := range map[string]struct {
		s    Spec
		want string
	}{
		"app type":      {Spec{AppType: "robot"}, "app_type"},
		"grant":         {Spec{AppType: "native", GrantTypes: []string{"magic"}}, "not supported"},
		"origin path":   {Spec{AppType: "spa", WebOrigins: []string{"https://a.test/x"}}, "web_origins"},
		"PAR off":       {Spec{AppType: "regular_web", RequirePushedAuthorizationRequests: true}, "pushed_authorization_requests_supported"},
		"device on spa": {Spec{AppType: "spa", GrantTypes: []string{GrantDeviceCode}}, "native"},
	} {
		errs := Normalize(&tc.s, false)
		if len(errs) == 0 || !strings.Contains(errs[0].Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, errs, tc.want)
		}
	}
	if got := DefaultGrantTypes(store.AuthMethodNone); len(got) != 2 {
		t.Errorf("public defaults = %v", got)
	}
}

// TestClientOrganizationFieldsValidation pins the observed client
// organization rules (D-0055): bad values are schema errors, the
// combination rules are ErrOrganizationRule.
func TestClientOrganizationFieldsValidation(t *testing.T) {
	usages := []string{"", store.OrgUsageDeny, store.OrgUsageAllow, store.OrgUsageRequire}
	behaviors := []string{"", store.OrgBehaviorNoPrompt, store.OrgBehaviorPreLoginPrompt, store.OrgBehaviorPostLoginPrompt}
	for _, u := range usages {
		for _, b := range behaviors {
			// pre_login_prompt is accepted with every usage (observed).
			if err := ValidateOrganizationFields(u, b, nil); err != nil {
				t.Errorf("%q/%q: %v", u, b, err)
			}
		}
		for _, m := range [][]string{{store.OrgDiscoveryEmail}, {store.OrgDiscoveryName}, {store.OrgDiscoveryEmail, store.OrgDiscoveryName}} {
			if err := ValidateOrganizationFields(u, store.OrgBehaviorPreLoginPrompt, m); err != nil {
				t.Errorf("%q with %v: %v", u, m, err)
			}
		}
	}
	for name, c := range map[string]struct {
		usage, behavior string
		methods         []string
		rule            bool
	}{
		"bad usage":                  {usage: "sometimes"},
		"bad behavior":               {behavior: "prompt"},
		"empty methods":              {behavior: store.OrgBehaviorPreLoginPrompt, methods: []string{}},
		"bad method":                 {behavior: store.OrgBehaviorPreLoginPrompt, methods: []string{"phone"}},
		"methods without a behavior": {methods: []string{store.OrgDiscoveryEmail}, rule: true},
		"methods with no_prompt":     {behavior: store.OrgBehaviorNoPrompt, methods: []string{store.OrgDiscoveryEmail}, rule: true},
		"methods with post_login":    {usage: store.OrgUsageRequire, behavior: store.OrgBehaviorPostLoginPrompt, methods: []string{store.OrgDiscoveryName}, rule: true},
	} {
		err := ValidateOrganizationFields(c.usage, c.behavior, c.methods)
		if err == nil || errors.Is(err, ErrOrganizationRule) != c.rule {
			t.Errorf("%s: err=%v, want rule=%v", name, err, c.rule)
		}
	}

	for _, g := range []string{GrantPassword, GrantPasswordRealm, GrantDeviceCode} {
		if err := CheckOrganizationGrants(store.OrgUsageRequire, []string{GrantAuthorizationCode, g}); !errors.Is(err, ErrOrganizationRule) {
			t.Errorf("require with %s: %v", g, err)
		}
		for _, u := range []string{"", store.OrgUsageDeny, store.OrgUsageAllow} {
			if err := CheckOrganizationGrants(u, []string{g}); err != nil {
				t.Errorf("%q with %s: %v", u, g, err)
			}
		}
	}
	if err := CheckOrganizationGrants(store.OrgUsageRequire, []string{GrantAuthorizationCode, GrantClientCredentials, GrantRefreshToken, GrantImplicit}); err != nil {
		t.Errorf("require with the allowed grants: %v", err)
	}

	// Normalize applies both, whoever writes the client.
	s := Spec{AppType: "regular_web", GrantTypes: []string{GrantPassword}, OrganizationUsage: store.OrgUsageRequire}
	if errs := Normalize(&s, false); len(errs) != 1 || !errors.Is(errs[0], ErrOrganizationRule) {
		t.Errorf("normalize require+password: %v", errs)
	}
	s = Spec{AppType: "regular_web", OrganizationUsage: "bogus"}
	if errs := Normalize(&s, false); len(errs) != 1 || errors.Is(errs[0], ErrOrganizationRule) {
		t.Errorf("normalize bad usage: %v", errs)
	}
}

// Plan 33b: client mobile is validated per ClientMobile* and the passkey
// grant is accepted for first-party applications only.
func TestClientMobileValidation(t *testing.T) {
	fp := strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	good := &store.ClientMobile{
		IOS:     &store.ClientMobileIOS{TeamID: "A1B2C3D4E5", AppBundleIdentifier: "com.acme.app"},
		Android: &store.ClientMobileAndroid{AppPackageName: "com.acme.app", SHA256CertFingerprints: []string{fp, strings.ToLower(fp)}},
	}
	s := Spec{AppType: "native", GrantTypes: []string{GrantPasskey, GrantRefreshToken}, Mobile: good}
	if errs := Normalize(&s, false); len(errs) > 0 {
		t.Fatal(errs)
	}
	for name, m := range map[string]*store.ClientMobile{
		"empty":         {},
		"ios only":      {IOS: &store.ClientMobileIOS{TeamID: "A1B2C3D4E5", AppBundleIdentifier: "com.acme.app"}},
		"unset strings": {IOS: &store.ClientMobileIOS{}, Android: &store.ClientMobileAndroid{}},
	} {
		s := Spec{AppType: "native", Mobile: m}
		if errs := Normalize(&s, false); len(errs) > 0 {
			t.Errorf("%s: %v", name, errs)
		}
	}
	for name, m := range map[string]*store.ClientMobile{
		"short team":        {IOS: &store.ClientMobileIOS{TeamID: "A1B2"}},
		"lower team":        {IOS: &store.ClientMobileIOS{TeamID: "a1b2c3d4e5"}},
		"bundle no dot":     {IOS: &store.ClientMobileIOS{AppBundleIdentifier: "acme"}},
		"bundle space":      {IOS: &store.ClientMobileIOS{AppBundleIdentifier: "com.acme app"}},
		"package digit":     {Android: &store.ClientMobileAndroid{AppPackageName: "com.1acme"}},
		"package dash":      {Android: &store.ClientMobileAndroid{AppPackageName: "com.acme-app"}},
		"no fingerprints":   {Android: &store.ClientMobileAndroid{SHA256CertFingerprints: []string{}}},
		"short fingerprint": {Android: &store.ClientMobileAndroid{SHA256CertFingerprints: []string{"AB:CD"}}},
		"bare hex":          {Android: &store.ClientMobileAndroid{SHA256CertFingerprints: []string{strings.Repeat("AB", 32)}}},
		"non-hex":           {Android: &store.ClientMobileAndroid{SHA256CertFingerprints: []string{strings.TrimSuffix(strings.Repeat("ZZ:", 32), ":")}}},
		"empty fingerprint": {Android: &store.ClientMobileAndroid{SHA256CertFingerprints: []string{""}}},
	} {
		s := Spec{AppType: "native", Mobile: m}
		errs := Normalize(&s, false)
		if len(errs) == 0 || !strings.Contains(errs[0].Error(), "mobile") {
			t.Errorf("%s: %v, want a mobile error", name, errs)
		}
	}
	third := false
	s = Spec{AppType: "native", IsFirstParty: &third, ThirdPartySecurityMode: store.SecurityModePermissive, GrantTypes: []string{GrantPasskey}}
	if errs := Normalize(&s, false); len(errs) == 0 || !strings.Contains(errs[0].Error(), "third-party") {
		t.Errorf("passkey grant on a third-party client: %v", errs)
	}
	if !slicesContains(GrantTypes, "urn:okta:params:oauth:grant-type:webauthn") || GrantPasskey != "urn:okta:params:oauth:grant-type:webauthn" {
		t.Errorf("GrantTypes = %v", GrantTypes)
	}
	// Mobile survives FromClient and Apply as an independent copy.
	c := &store.Client{Name: "native", AppType: store.AppTypeNative, TokenEndpointAuthMethod: store.AuthMethodNone, IsFirstParty: true,
		RedirectionPolicy: store.RedirectionPolicyAllowAlways, Mobile: good}
	spec := FromClient(c)
	got := &store.Client{}
	Apply(got, &spec)
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, c)
	}
	got.Mobile.Android.SHA256CertFingerprints[0] = "changed"
	if good.Android.SHA256CertFingerprints[0] != fp {
		t.Fatal("Apply shares the fingerprint list")
	}
}

func slicesContains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
