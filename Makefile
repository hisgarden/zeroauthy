.PHONY: e2e-passwordless e2e-mfa e2e-events e2e-logs e2e-organizations-ii e2e-organizations build test test-sql lint generate check-sources e2e e2e-actions e2e-actions-ii e2e-rbac e2e-email-accounts e2e-social e2e-deploy e2e-signing e2e-email e2e-branding e2e-domains conformance console

build:
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy ./cmd/zeroauthy
	CGO_ENABLED=0 go build -trimpath -o bin/zeroauthy-store-memory ./cmd/zeroauthy-store-memory

test:
	go test ./...

test-sql:
	./scripts/test-sql.sh

lint:
	go vet ./...

generate:
	go generate ./...

check-sources:
	./scripts/check-sources.sh api/authentication.yaml
	./scripts/check-sources.sh api/management.yaml

e2e:
	./tests/e2e/run-m3.sh
	./tests/e2e/run-browser.sh

e2e-passwordless:
	./tests/e2e/run-m34-passwordless.sh

e2e-mfa:
	./tests/e2e/run-m33-mfa.sh

e2e-events:
	./tests/e2e/run-m32-events.sh

e2e-logs:
	./tests/e2e/run-m31-logs.sh

e2e-actions:
	./tests/e2e/run-m27-actions.sh

e2e-organizations-ii:
	./tests/e2e/run-m30-organizations-ii.sh

e2e-organizations:
	./tests/e2e/run-m29-organizations.sh

e2e-rbac:
	./tests/e2e/run-m26-rbac.sh

e2e-email-accounts:
	./tests/e2e/run-m25-email-accounts.sh

e2e-social:
	./tests/e2e/run-m24-social.sh

e2e-deploy:
	./tests/e2e/run-m20-deploy.sh

e2e-signing:
	./tests/e2e/run-m20-signing.sh

e2e-email:
	./tests/e2e/run-m21-email.sh

e2e-branding:
	./tests/e2e/run-m22-branding.sh

e2e-domains:
	./tests/e2e/domains/run-acme.sh http01,tlsalpn,dns01
	./tests/e2e/run-m23-domains.sh

conformance:
	./tests/conformance/run.sh $(PLANS)

# The admin console: install, lint, typecheck, test, regenerate the API
# types and rebuild console/dist (committed, embedded by go:embed). The
# toolchain is Bun; --bun runs the tools on Bun's runtime instead of the
# Node their bin scripts' shebang names. The one exception is typecheck:
# vue-tsc patches TypeScript's tsc at load time through Node's module hooks,
# and under Bun's runtime (bun 1.4.4) the patch does not apply, so it
# silently type-checks no .vue file and misreports component props. Without
# --bun it runs on the Node from PATH until Bun supports it.
console:
	cd console && bun install --frozen-lockfile
	cd console && bun --bun run gen && bun --bun run lint && bun run typecheck && bun --bun run test && bun --bun run build

e2e-actions-ii:
	./tests/e2e/run-m28-actions-ii.sh
