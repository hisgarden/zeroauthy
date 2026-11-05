package sbomcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": {"type": "file", "name": "zeroauthy_1.2.3_linux_amd64", "version": "1.2.3"}
  },
  "components": [
    {"type": "library", "name": "github.com/zeroauthy/zeroauthy", "purl": "pkg:golang/github.com/zeroauthy/zeroauthy"},
    {"type": "library", "name": "golang.org/x/crypto", "version": "v0.58.0", "purl": "pkg:golang/golang.org/x/crypto@v0.58.0"},
    {"type": "library", "name": "vue", "version": "3.5.43", "purl": "pkg:npm/vue@3.5.43"}
  ]
}`

const validSPDX = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "zeroauthy_1.2.3_linux_amd64",
  "documentNamespace": "https://example.invalid/zeroauthy/1.2.3",
  "creationInfo": {"created": "2026-11-05T00:00:00Z", "creators": ["Tool: syft-1.56.0"]},
  "packages": [
    {"name": "vue", "SPDXID": "SPDXRef-Package-npm-vue", "versionInfo": "3.5.43", "downloadLocation": "NOASSERTION",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/vue@3.5.43"}]},
    {"name": "golang.org/x/crypto", "SPDXID": "SPDXRef-Package-go-crypto", "versionInfo": "v0.58.0", "downloadLocation": "NOASSERTION",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/golang.org/x/crypto@v0.58.0"}]}
  ]
}`

func TestCheckCycloneDXValid(t *testing.T) {
	sum, err := CheckCycloneDX([]byte(validCycloneDX))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Format != "CycloneDX" || sum.SpecVersion != "1.6" || sum.Name != "zeroauthy_1.2.3_linux_amd64" || sum.Version != "1.2.3" || sum.Components != 3 {
		t.Fatalf("summary %+v", sum)
	}
	if err := sum.Require(Requirement{Go: true, Console: true}); err != nil {
		t.Fatal(err)
	}
	if err := sum.Require(Requirement{OS: true}); err == nil || !strings.Contains(err.Error(), "pkg:apk/") {
		t.Fatalf("OS requirement: %v", err)
	}
}

func TestCheckCycloneDXRejects(t *testing.T) {
	cases := map[string]struct{ doc, want string }{
		"wrong specVersion": {strings.Replace(validCycloneDX, `"1.6"`, `"1.5"`, 1), "specVersion"},
		"missing bomFormat": {strings.Replace(validCycloneDX, `"bomFormat": "CycloneDX",`, ``, 1), "bomFormat"},
		"schema violation":  {strings.Replace(validCycloneDX, `"type": "library", "name": "vue"`, `"type": "gadget", "name": "vue"`, 1), "schema"},
		"no serial":         {strings.Replace(validCycloneDX, `"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",`, ``, 1), "serialNumber"},
		"no components":     {validCycloneDX[:strings.Index(validCycloneDX, `"components"`)] + `"components": []}`, "components"},
		"not JSON":          {"nope", "JSON"},
	}
	for name, c := range cases {
		_, err := CheckCycloneDX([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want %q", name, err, c.want)
		}
	}
}

func TestRequireConsoleRejectsDevTools(t *testing.T) {
	doc := strings.Replace(validCycloneDX, `{"type": "library", "name": "vue"`,
		`{"type": "library", "name": "vitest", "version": "5.0.3", "purl": "pkg:npm/vitest@5.0.3"}, {"type": "library", "name": "vue"`, 1)
	sum, err := CheckCycloneDX([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	err = sum.Require(Requirement{Console: true})
	if err == nil || !strings.Contains(err.Error(), "vitest") {
		t.Fatalf("err=%v", err)
	}
	noConsole := strings.Replace(validCycloneDX, "pkg:npm/vue@3.5.43", "pkg:npm/other@1.0.0", 1)
	sum, err = CheckCycloneDX([]byte(noConsole))
	if err != nil {
		t.Fatal(err)
	}
	if err := sum.Require(Requirement{Console: true}); err == nil || !strings.Contains(err.Error(), "pkg:npm/vue@") {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckSPDX(t *testing.T) {
	sum, err := CheckSPDX([]byte(validSPDX))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Format != "SPDX" || sum.SpecVersion != "SPDX-2.3" || sum.Components != 2 || len(sum.Purls) != 2 {
		t.Fatalf("summary %+v", sum)
	}
	if err := sum.Require(Requirement{Go: true, Console: true}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct{ doc, want string }{
		"wrong version": {strings.Replace(validSPDX, "SPDX-2.3", "SPDX-2.2", 1), "spdxVersion"},
		"wrong license": {strings.Replace(validSPDX, "CC0-1.0", "MIT", 1), "dataLicense"},
		"wrong SPDXID":  {strings.Replace(validSPDX, `"SPDXID": "SPDXRef-DOCUMENT"`, `"SPDXID": "SPDXRef-X"`, 1), "SPDXID"},
		"no namespace":  {strings.Replace(validSPDX, `"documentNamespace": "https://example.invalid/zeroauthy/1.2.3",`, ``, 1), "documentNamespace"},
		"no created":    {strings.Replace(validSPDX, `"created": "2026-11-05T00:00:00Z",`, ``, 1), "creationInfo.created"},
		"no packages":   {validSPDX[:strings.Index(validSPDX, `"packages"`)] + `"packages": []}`, "packages"},
		"not an object": {"[]", "JSON object"},
	}
	for name, c := range cases {
		_, err := CheckSPDX([]byte(c.doc))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want %q", name, err, c.want)
		}
	}
}

func TestCheckDirStrict(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("zeroauthy_1.2.3_linux_amd64.cdx.json", validCycloneDX)
	write("zeroauthy_1.2.3_linux_amd64.spdx.json", validSPDX)
	results, err := CheckDir(dir, true)
	if err != nil {
		t.Fatalf("strict pair: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results %d", len(results))
	}

	// An image SBOM needs OS packages, not the console; this one has neither apk nor an SPDX twin.
	write("zeroauthy_1.2.3_image.cdx.json", validCycloneDX)
	_, err = CheckDir(dir, true)
	if err == nil || !strings.Contains(err.Error(), "pkg:apk/") || !strings.Contains(err.Error(), "no SPDX counterpart") {
		t.Fatalf("strict image: %v", err)
	}
	// Lenient mode validates each file on its own.
	if _, err := CheckDir(dir, false); err != nil {
		t.Fatalf("lenient: %v", err)
	}
	if _, err := CheckDir(filepath.Join(dir, "missing"), false); err == nil {
		t.Fatal("empty dir accepted")
	}
}

// TestGeneratedSBOMs checks the SBOMs scripts/sbom.sh wrote (scripts/check-sbom.sh
// sets ZA_SBOM_DIR and, in CI, ZA_SBOM_STRICT=1). It is skipped otherwise.
func TestGeneratedSBOMs(t *testing.T) {
	dir := os.Getenv("ZA_SBOM_DIR")
	if dir == "" {
		t.Skip("ZA_SBOM_DIR is not set")
	}
	strict := os.Getenv("ZA_SBOM_STRICT") == "1"
	results, err := CheckDir(dir, strict)
	for _, r := range results {
		if r.Summary != nil {
			t.Logf("%s: %s %s, %d components, %s %s", filepath.Base(r.File), r.Summary.Format, r.Summary.SpecVersion, r.Summary.Components, r.Summary.Name, r.Summary.Version)
		}
	}
	if err != nil {
		t.Fatalf("SBOM contract (strict=%v):\n%v", strict, err)
	}
}
