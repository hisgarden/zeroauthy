// Package rpid resolves the WebAuthn relying party ID and the allowed
// origins of the host a request used (Plan 33b spec sections 3.2 and 7.3,
// resolutions R1 and R2 in D-0062). Passkeys and WebAuthn MFA share it, so
// one host has one RP ID.
//
// The canonical host's RP ID is always the host itself. A verified custom
// domain uses its relying_party_identifier, else the domain; an operator
// alias uses Tenant.DomainRPIDs[host], else the host. A stored RP ID that is
// not a registrable suffix of its host, or that the deployment's strict
// sharing rule refuses, is never replaced: the Result is not Valid and
// ceremonies on that host fail closed.
package rpid

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Kind is the kind of host a request used.
type Kind string

const (
	KindCanonical Kind = "canonical" // the tenant's canonical host
	KindCustom    Kind = "custom"    // a verified custom domain (Management API)
	KindOperator  Kind = "operator"  // an operator alias (seed domains, R2)
)

// Problems name why a Result is not Valid. They go to logs and the console,
// never to an end user.
const (
	ProblemNoTenant     = "no_tenant"
	ProblemUnknownHost  = "unknown_host" // no active browser-facing claim of this tenant
	ProblemIPHost       = "ip_host"      // an IP literal cannot be an RP ID
	ProblemNotSuffix    = "not_registrable_suffix"
	ProblemSharedRefuse = "shared_rp_id_restricted" // security.webauthn.restrict_shared_rp_ids
)

// ErrInvalid is Validate's only refusal. Its message is fixed: it never says
// which rule applied, so it cannot reveal another tenant's hosts.
var ErrInvalid = fmt.Errorf("rpid: the relying party identifier is not allowed for this host: %w", store.ErrInvalid)

// Result is the effective RP ID of one request host. Origin is the exact
// serialized origin hosted ceremonies accept: https, the lowercase host
// without a trailing dot, and the port unless it is 443. RPID is the bare
// hostname, or the stored override. When Valid is false, Problem says why
// and every ceremony on the host must fail.
type Result struct {
	RPID, Origin string
	Kind         Kind
	Valid        bool
	Problem      string
}

// Policy holds the deployment's RP ID rules. BaseDomain is
// server.base_domain, SystemHost the system tenant's host and OriginSuffix
// server.origin_domain; they matter only with RestrictShared
// (security.webauthn.restrict_shared_rp_ids). Store reads host claims and
// custom domains; a nil Store resolves from the tenant's own fields only.
type Policy struct {
	BaseDomain, SystemHost, OriginSuffix string
	RestrictShared                       bool
	Store                                store.Store
}

// For resolves res's effective RP ID and hosted origin. An unusable RP ID is
// a Result with Valid false (one WARN is logged with the tenant and host);
// the error is only for storage failures.
func (p Policy) For(ctx context.Context, res tenant.Resolved) (Result, error) {
	host := tenant.NormalizeHost(res.Host)
	name := bareName(host)
	r := Result{RPID: name, Origin: "https://" + host}
	if res.Tenant == nil {
		r.Problem = ProblemNoTenant
		return r, nil
	}
	kind, override, err := p.kind(ctx, res.Tenant, host)
	if err != nil {
		return Result{}, err
	}
	r.Kind = kind
	if override != "" {
		r.RPID = strings.TrimSuffix(strings.ToLower(override), ".")
	}
	switch {
	case kind == "":
		r.Problem = ProblemUnknownHost
	case net.ParseIP(name) != nil:
		r.Problem = ProblemIPHost
	case kind != KindCanonical:
		// The canonical host's RP ID is itself and is never checked
		// against the sharing rule (R1).
		var rp string
		rp, r.Problem, err = p.check(ctx, res.Tenant.ID, name, r.RPID)
		if err != nil {
			return Result{}, err
		}
		if r.Problem == "" {
			r.RPID = rp
		}
	}
	r.Valid = r.Problem == ""
	if !r.Valid {
		slog.Default().WarnContext(ctx, "webauthn: relying party ID unusable on this host; passkey and WebAuthn ceremonies fail closed",
			"tenant", res.Tenant.ID, "host", host, "rp_id", r.RPID, "problem", r.Problem)
	}
	return r, nil
}

// Validate applies the R1 rule to rpID for host, a host of tenantID (a
// custom domain or an operator alias, with or without a port): a
// registrable suffix of the host at most webauthnrules.Limits.RPIDMax long
// and, with RestrictShared, not covering the base domain, system host,
// origin suffix or another tenant's host. Every refusal is ErrInvalid; other
// errors are storage failures (the strict rule fails closed without them).
func (p Policy) Validate(ctx context.Context, tenantID, host, rpID string) error {
	name := bareName(tenant.NormalizeHost(host))
	if net.ParseIP(name) != nil {
		return ErrInvalid
	}
	_, problem, err := p.check(ctx, tenantID, name, rpID)
	if err != nil {
		return err
	}
	if problem != "" {
		return ErrInvalid
	}
	return nil
}

// check returns the normalized RP ID, or the problem that refuses it.
func (p Policy) check(ctx context.Context, tenantID, name, rpID string) (string, string, error) {
	rp, err := customdomain.ValidateRPID(name, rpID)
	if err != nil {
		return "", ProblemNotSuffix, nil
	}
	if !p.RestrictShared {
		return rp, "", nil
	}
	for _, reserved := range []string{p.BaseDomain, p.SystemHost, p.OriginSuffix} {
		if n := bareName(tenant.NormalizeHost(reserved)); n != "" && (n == rp || strings.HasSuffix(n, "."+rp)) {
			return "", ProblemSharedRefuse, nil
		}
	}
	if p.Store == nil {
		return "", "", errors.New("rpid: the shared relying party ID rule needs a store")
	}
	// Two IDs suffice: the list is distinct, so a second one is another
	// tenant whenever the first is this one.
	owners, err := p.Store.WebAuthn().HostTenantsUnder(ctx, rp, 2)
	if err != nil {
		return "", "", fmt.Errorf("rpid: hosts under the relying party ID: %w", err)
	}
	if slices.ContainsFunc(owners, func(id string) bool { return id != tenantID }) {
		return "", ProblemSharedRefuse, nil
	}
	return rp, "", nil
}

// kind classifies host (normalized, with any port) for t and returns the
// stored RP ID override. An empty Kind means t does not serve host.
func (p Policy) kind(ctx context.Context, t *store.Tenant, host string) (Kind, string, error) {
	if host == "" {
		return "", "", nil
	}
	if t.CanonicalHost != "" && host == t.CanonicalHost {
		return KindCanonical, "", nil
	}
	if p.Store != nil {
		b, err := p.Store.CustomDomains().GetHost(ctx, host)
		switch {
		case err == nil:
			if b.TenantID != t.ID || !b.Active {
				return "", "", nil
			}
			switch b.Kind {
			case store.HostCanonical:
				return KindCanonical, "", nil
			case store.HostOperator:
				return KindOperator, t.DomainRPIDs[host], nil
			case store.HostPublic:
				d, err := p.Store.CustomDomains().Get(ctx, t.ID, b.DomainID)
				if errors.Is(err, store.ErrNotFound) {
					return "", "", nil
				}
				if err != nil {
					return "", "", err
				}
				return KindCustom, d.RelyingPartyIdentifier, nil
			default: // origin aliases are never browser origins
				return "", "", nil
			}
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrCustomDomainRepositoryUnavailable):
		default:
			return "", "", err
		}
	}
	// No claim: a tenant whose operator hosts predate the host registry.
	if slices.Contains(t.Domains, host) {
		if t.CanonicalHost == "" {
			return KindCanonical, "", nil
		}
		return KindOperator, t.DomainRPIDs[host], nil
	}
	return "", "", nil
}

// bareName is a normalized host without its port or IPv6 brackets.
func bareName(host string) string {
	if name, _, err := net.SplitHostPort(host); err == nil {
		return name
	}
	return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
}
