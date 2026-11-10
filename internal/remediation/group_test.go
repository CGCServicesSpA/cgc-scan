package remediation

import (
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func fp(n int) string { return strings.Repeat(string("abcdef0123456789"[n%16]), 32) }

func vuln(id, pkg, version, fixed string, severity normalize.Severity, direct bool) normalize.Finding {
	d := direct
	return normalize.Finding{
		Fingerprint: id, Kind: normalize.KindVulnerability, Title: "CVE " + id,
		Severity:  normalize.SeverityInfo{Normalized: severity, Source: "trivy"},
		Sources:   []normalize.SourceRef{{Engine: "trivy", Version: "0.76.1"}},
		Locations: []normalize.Location{{Path: "go.mod"}},
		Package: &normalize.PackageRef{
			Ecosystem: "Go", Name: pkg, Version: version, FixedVersion: &fixed, Direct: &d,
		},
		IDs:    []normalize.Identifier{{Type: "CVE", Value: "CVE-" + id}},
		Policy: normalize.FindingPolicy{Status: "active"},
	}
}

func docWith(findings ...normalize.Finding) *report.Document {
	d := &report.Document{
		Target: report.Target{Root: "/p", Units: []report.UnitInfo{{ID: "project", Path: ".", Kind: "repository"}}},
		Validation: report.Validation{
			Recipes: []report.Recipe{
				{Unit: "project", Kind: "test", Command: "go test ./...", Workdir: ".", Origin: "user"},
				{Unit: "project", Kind: "build", Command: "go build ./...", Workdir: ".", Origin: "user"},
			},
			Unresolved: []report.Unresolved{},
		},
		Findings: findings, Errors: []report.Error{},
	}
	return d
}

func TestGroupsXTextSingleAction(t *testing.T) {
	findings := []normalize.Finding{
		vuln(fp(1), "golang.org/x/text", "v0.3.0", "0.3.3", normalize.SeverityHigh, true),
		vuln(fp(2), "golang.org/x/text", "v0.3.0", "0.3.7", normalize.SeverityMedium, true),
		vuln(fp(3), "golang.org/x/text", "v0.3.0", "0.3.8", normalize.SeverityHigh, true),
		vuln(fp(4), "golang.org/x/text", "v0.3.0", "0.41.0", normalize.SeverityLow, true),
		vuln(fp(5), "golang.org/x/text", "v0.3.0", "0.39.0", normalize.SeverityMedium, true),
	}
	ApplyPriority(findings)
	got := Build(docWith(findings...))
	if len(got) != 1 {
		t.Fatalf("grupos = %d: %+v", len(got), got)
	}
	g := got[0]
	if g.ID != "rg-go-golang.org/x/text" {
		t.Errorf("id = %q", g.ID)
	}
	if g.Package == nil || g.Package.To != "v0.41.0" {
		t.Errorf("destino = %+v", g.Package)
	}
	if len(g.Fixes) != 5 {
		t.Errorf("fixes = %v", g.Fixes)
	}
	if g.BreakingRisk != "minor" {
		t.Errorf("riesgo = %q", g.BreakingRisk)
	}
	if g.Commands.Apply != "go get golang.org/x/text@v0.41.0 && go mod tidy" {
		t.Errorf("comando = %q", g.Commands.Apply)
	}
	if g.Commands.Origin != "cgc-scan" {
		t.Errorf("origen = %q", g.Commands.Origin)
	}
	if g.Verification.Status != "ready" || g.Verification.Verify != "cgc-scan verify rg-go-golang.org/x/text" {
		t.Errorf("verificación = %+v", g.Verification)
	}
	if g.MaxSeverity != normalize.SeverityHigh {
		t.Errorf("severidad = %q", g.MaxSeverity)
	}
}

func TestGroupsByEcosystemCommands(t *testing.T) {
	tests := []struct {
		eco, name, from, fixed, want string
	}{
		{"npm", "lodash", "4.17.0", "4.17.21", "npm install lodash@4.17.21"},
		{"crates.io", "time", "0.1.0", "0.1.45", "cargo update -p time --precise 0.1.45"},
		{"PyPI", "django", "3.0.0", "3.2.25", "pip install django==3.2.25"},
		{"Packagist", "symfony/http-foundation", "v4.0.0", "v4.4.0", "composer require symfony/http-foundation:v4.4.0 --with-all-dependencies"},
	}
	for _, tt := range tests {
		f := normalize.Finding{
			Fingerprint: fp(1), Kind: normalize.KindVulnerability, Title: "x",
			Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityHigh, Source: "trivy"},
			Sources:   []normalize.SourceRef{{Engine: "trivy"}},
			Locations: []normalize.Location{{Path: "lock"}},
			Package:   &normalize.PackageRef{Ecosystem: tt.eco, Name: tt.name, Version: tt.from, FixedVersion: &tt.fixed},
			Policy:    normalize.FindingPolicy{Status: "active"},
		}
		got := Build(docWith(f))
		if len(got) != 1 || got[0].Commands.Apply != tt.want {
			t.Errorf("%s: %+v", tt.eco, got)
		}
	}
}

func TestGroupsCodeByFileAndRule(t *testing.T) {
	mk := func(id, path string, line int) normalize.Finding {
		return normalize.Finding{
			Fingerprint: id, Kind: normalize.KindCode, Title: "objeto inyectado",
			Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityMedium, Source: "eslint"},
			Sources:   []normalize.SourceRef{{Engine: "eslint", Rule: "detect-object-injection"}},
			Locations: []normalize.Location{{Path: path, StartLine: &line}},
			Evidence:  normalize.Evidence{Redacted: true},
			Policy:    normalize.FindingPolicy{Status: "active"},
		}
	}
	got := Build(docWith(
		mk(fp(1), "src/catalog-forms.mjs", 10),
		mk(fp(2), "src/catalog-forms.mjs", 20),
		mk(fp(3), "src/other.mjs", 5),
	))
	if len(got) != 2 {
		t.Fatalf("grupos = %d: %+v", len(got), got)
	}
	if got[0].Kind != "code_fix" || got[0].File != "src/catalog-forms.mjs" || got[0].Locations != 2 {
		t.Fatalf("grupo = %+v", got[0])
	}
	if got[0].Commands.Apply != "" || len(got[0].Fixes) != 2 {
		t.Fatalf("comando/grupo = %+v", got[0])
	}
}

func TestGroupsSecretsRequireRotation(t *testing.T) {
	f := normalize.Finding{
		Fingerprint: fp(1), Kind: normalize.KindSecret, Title: "token",
		Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityCritical, Source: "trivy"},
		Sources:   []normalize.SourceRef{{Engine: "trivy", Rule: "github-pat"}},
		Locations: []normalize.Location{{Path: ".env"}},
		Policy:    normalize.FindingPolicy{Status: "active"},
	}
	got := Build(docWith(f))
	if len(got) != 1 || got[0].Kind != "secret_rotation" {
		t.Fatalf("grupos = %+v", got)
	}
	if got[0].Verification.Status != "blocked" || got[0].Verification.Note == "" {
		t.Fatalf("verificación = %+v", got[0].Verification)
	}
}

func TestGroupsTransitiveSuggestsOverride(t *testing.T) {
	f := vuln(fp(1), "golang.org/x/text", "v0.3.0", "0.41.0", normalize.SeverityHigh, false)
	f.Package.Via = "example.com/parent"
	f.Package.Relationship = "transitive"
	got := Build(docWith(f))
	if len(got) != 1 {
		t.Fatalf("grupos = %+v", got)
	}
	if got[0].Direct == nil || *got[0].Direct {
		t.Fatalf("direct = %v", got[0].Direct)
	}
	if !strings.Contains(got[0].Commands.Override, "go mod edit -replace") {
		t.Fatalf("override = %q", got[0].Commands.Override)
	}
	if !strings.Contains(got[0].Note, "example.com/parent") {
		t.Fatalf("nota = %q", got[0].Note)
	}
}
