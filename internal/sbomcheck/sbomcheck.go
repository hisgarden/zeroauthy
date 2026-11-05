// Package sbomcheck guards the contract of the SBOMs a zeroauthy release
// publishes (Plan 49, docs/supply-chain.md): a CycloneDX 1.6 document that
// validates against the vendored JSON schema and an SPDX 2.3 document with
// the fields the specification requires, each describing one release
// artefact and listing the Go modules linked into it, the console's
// production npm dependencies and, for the image, its OS packages.
//
// scripts/check-sbom.sh runs TestGeneratedSBOMs against dist/sbom; CI runs
// the same script in strict mode before the vulnerability gate.
package sbomcheck

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The CycloneDX 1.6 schema and the two schemas it references, copied from
// https://github.com/CycloneDX/specification (schema/, Apache-2.0; see
// NOTICE). The $id of each file is http://cyclonedx.org/schema/<name>.
//
//go:embed schema/bom-1.6.schema.json schema/spdx.schema.json schema/jsf-0.82.schema.json
var schemaFS embed.FS

const (
	schemaBase     = "http://cyclonedx.org/schema/"
	cycloneDXMain  = "bom-1.6.schema.json"
	cycloneDXSpec  = "1.6"
	spdxVersion    = "SPDX-2.3"
	spdxLicense    = "CC0-1.0"
	spdxDocumentID = "SPDXRef-DOCUMENT"
)

var compileCycloneDX = sync.OnceValues(func() (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	for _, name := range []string{cycloneDXMain, "spdx.schema.json", "jsf-0.82.schema.json"} {
		raw, err := schemaFS.ReadFile("schema/" + name)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if err := c.AddResource(schemaBase+name, doc); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return c.Compile(schemaBase + cycloneDXMain)
})

// Summary is what a checked document says about itself.
type Summary struct {
	Format      string // "CycloneDX" or "SPDX"
	SpecVersion string // "1.6" or "SPDX-2.3"
	Name        string // metadata.component.name, or the SPDX document name
	Version     string // metadata.component.version ("" for SPDX)
	Components  int    // components (CycloneDX) or packages (SPDX)
	Purls       []string
}

// Requirement names the package ecosystems a document must cover.
type Requirement struct {
	Go      bool // at least one pkg:golang/ purl
	Console bool // the console's production tree: pkg:npm/vue@, and no dev-only tool
	OS      bool // at least one pkg:apk/ purl (the image's Wolfi packages)
}

// Development-only npm tools that must never appear in a release SBOM: they
// build and test the console but are not part of what ships.
var devOnlyNPM = []string{"vitest", "eslint", "vite", "vue-tsc", "typescript-eslint", "happy-dom"}

// CheckCycloneDX validates data against the CycloneDX 1.6 schema and the
// release contract: bomFormat, specVersion 1.6, a serial number, a metadata
// component naming the artefact, and at least one component.
func CheckCycloneDX(data []byte) (*Summary, error) {
	schema, err := compileCycloneDX()
	if err != nil {
		return nil, fmt.Errorf("compile CycloneDX schema: %w", err)
	}
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return nil, errors.New("not a JSON object")
	}
	if got, _ := m["bomFormat"].(string); got != "CycloneDX" {
		return nil, fmt.Errorf("bomFormat is %q, want CycloneDX", got)
	}
	if got, _ := m["specVersion"].(string); got != cycloneDXSpec {
		return nil, fmt.Errorf("specVersion is %q, want %s", got, cycloneDXSpec)
	}
	if err := schema.Validate(doc); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	if s, _ := m["serialNumber"].(string); s == "" {
		return nil, errors.New("serialNumber is missing")
	}
	meta, _ := m["metadata"].(map[string]any)
	comp, _ := meta["component"].(map[string]any)
	sum := &Summary{Format: "CycloneDX", SpecVersion: cycloneDXSpec}
	sum.Name, _ = comp["name"].(string)
	sum.Version, _ = comp["version"].(string)
	if sum.Name == "" {
		return nil, errors.New("metadata.component.name is missing")
	}
	comps, _ := m["components"].([]any)
	for _, c := range comps {
		cm, _ := c.(map[string]any)
		if p, _ := cm["purl"].(string); p != "" {
			sum.Purls = append(sum.Purls, p)
		}
	}
	sum.Components = len(comps)
	if sum.Components == 0 {
		return nil, errors.New("components is empty")
	}
	sort.Strings(sum.Purls)
	return sum, nil
}

// CheckSPDX checks the SPDX 2.3 fields the specification requires of a JSON
// document (the SPDX JSON schema is not vendored, see the design spec) and
// that it lists at least one package.
func CheckSPDX(data []byte) (*Summary, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if got, _ := m["spdxVersion"].(string); got != spdxVersion {
		return nil, fmt.Errorf("spdxVersion is %q, want %s", got, spdxVersion)
	}
	if got, _ := m["dataLicense"].(string); got != spdxLicense {
		return nil, fmt.Errorf("dataLicense is %q, want %s", got, spdxLicense)
	}
	if got, _ := m["SPDXID"].(string); got != spdxDocumentID {
		return nil, fmt.Errorf("SPDXID is %q, want %s", got, spdxDocumentID)
	}
	for _, key := range []string{"name", "documentNamespace"} {
		if v, _ := m[key].(string); v == "" {
			return nil, fmt.Errorf("%s is missing", key)
		}
	}
	ci, _ := m["creationInfo"].(map[string]any)
	if v, _ := ci["created"].(string); v == "" {
		return nil, errors.New("creationInfo.created is missing")
	}
	sum := &Summary{Format: "SPDX", SpecVersion: spdxVersion}
	sum.Name, _ = m["name"].(string)
	pkgs, _ := m["packages"].([]any)
	for _, p := range pkgs {
		pm, _ := p.(map[string]any)
		refs, _ := pm["externalRefs"].([]any)
		for _, r := range refs {
			rm, _ := r.(map[string]any)
			if t, _ := rm["referenceType"].(string); t == "purl" {
				if loc, _ := rm["referenceLocator"].(string); loc != "" {
					sum.Purls = append(sum.Purls, loc)
				}
			}
		}
	}
	sum.Components = len(pkgs)
	if sum.Components == 0 {
		return nil, errors.New("packages is empty")
	}
	sort.Strings(sum.Purls)
	return sum, nil
}

// Require reports which ecosystems r asks for that s does not cover, and
// any development-only npm tool present when the console is required.
func (s *Summary) Require(r Requirement) error {
	var problems []string
	has := func(prefix string) bool {
		for _, p := range s.Purls {
			if strings.HasPrefix(p, prefix) {
				return true
			}
		}
		return false
	}
	if r.Go && !has("pkg:golang/") {
		problems = append(problems, "no pkg:golang/ component (Go modules missing)")
	}
	if r.Console {
		if !has("pkg:npm/vue@") {
			problems = append(problems, "no pkg:npm/vue@ component (console dependencies missing; syft >= 1.46.0 is needed for bun.lock)")
		}
		for _, tool := range devOnlyNPM {
			if has("pkg:npm/" + tool + "@") {
				problems = append(problems, "development-only npm tool "+tool+" is listed")
			}
		}
	}
	if r.OS && !has("pkg:apk/") {
		problems = append(problems, "no pkg:apk/ component (image OS packages missing)")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Result is the outcome for one file in a directory check.
type Result struct {
	File    string
	Summary *Summary
	Err     error
}

// CheckDir checks every *.cdx.json and *.spdx.json file in dir. In strict
// mode each artefact must have both formats, archive SBOMs must cover Go
// and the console, and the image SBOM (name ending in "_image") must cover
// Go and the OS packages. The returned error summarises every failure.
func CheckDir(dir string, strict bool) ([]Result, error) {
	cdx, err := filepath.Glob(filepath.Join(dir, "*.cdx.json"))
	if err != nil {
		return nil, err
	}
	spdx, err := filepath.Glob(filepath.Join(dir, "*.spdx.json"))
	if err != nil {
		return nil, err
	}
	if len(cdx)+len(spdx) == 0 {
		return nil, fmt.Errorf("%s: no *.cdx.json or *.spdx.json files", dir)
	}
	var results []Result
	var failures []string
	check := func(file string, fn func([]byte) (*Summary, error)) {
		res := Result{File: file}
		data, err := os.ReadFile(file)
		if err == nil {
			res.Summary, err = fn(data)
		}
		if err == nil && strict {
			err = res.Summary.Require(requirementFor(file))
		}
		res.Err = err
		if err != nil {
			failures = append(failures, filepath.Base(file)+": "+err.Error())
		}
		results = append(results, res)
	}
	for _, f := range cdx {
		check(f, CheckCycloneDX)
	}
	for _, f := range spdx {
		check(f, CheckSPDX)
	}
	if strict {
		for _, f := range cdx {
			other := strings.TrimSuffix(f, ".cdx.json") + ".spdx.json"
			if _, err := os.Stat(other); err != nil {
				failures = append(failures, filepath.Base(f)+": no SPDX counterpart "+filepath.Base(other))
			}
		}
		for _, f := range spdx {
			other := strings.TrimSuffix(f, ".spdx.json") + ".cdx.json"
			if _, err := os.Stat(other); err != nil {
				failures = append(failures, filepath.Base(f)+": no CycloneDX counterpart "+filepath.Base(other))
			}
		}
	}
	if len(failures) > 0 {
		return results, errors.New(strings.Join(failures, "\n"))
	}
	return results, nil
}

// requirementFor derives the strict requirement from the file name:
// zeroauthy_<v>_image.* is the container image, anything else an archive.
func requirementFor(file string) Requirement {
	base := filepath.Base(file)
	stem := base[:len(base)-len(filepath.Ext(base))] // drop .json
	stem = strings.TrimSuffix(strings.TrimSuffix(stem, ".cdx"), ".spdx")
	if strings.HasSuffix(stem, "_image") {
		return Requirement{Go: true, OS: true}
	}
	return Requirement{Go: true, Console: true}
}
