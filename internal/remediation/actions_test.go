package remediation

import (
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func TestPriorityFactorsAndOrder(t *testing.T) {
	kev := true
	reachable := true
	direct := true
	fixed := "2.0.0"
	high := normalize.Finding{
		Fingerprint: fp(1), Kind: normalize.KindVulnerability, Title: "high",
		Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityHigh, Source: "trivy"},
		Sources:   []normalize.SourceRef{{Engine: "trivy"}},
		Locations: []normalize.Location{{Path: "go.mod"}},
		Package: &normalize.PackageRef{
			Ecosystem: "Go", Name: "x", Version: "1.0.0", FixedVersion: &fixed, Direct: &direct,
		},
		Priority: &normalize.Priority{KEV: &kev, Reachable: &reachable, EPSS: ptr(0.7)},
		Policy:   normalize.FindingPolicy{Status: "active"},
	}
	testHigh := high
	testHigh.Fingerprint = fp(2)
	testHigh.Locations = []normalize.Location{{Path: "test/fixture.go"}}
	pkgCopy := *high.Package
	testHigh.Package = &pkgCopy
	prioCopy := *high.Priority
	testHigh.Priority = &prioCopy
	low := normalize.Finding{
		Fingerprint: fp(3), Kind: normalize.KindCode, Title: "low",
		Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityLow, Source: "eslint"},
		Sources:   []normalize.SourceRef{{Engine: "eslint"}},
		Locations: []normalize.Location{{Path: "src/a.js"}},
		Policy:    normalize.FindingPolicy{Status: "active"},
	}
	findings := []normalize.Finding{low, testHigh, high}
	ApplyPriority(findings)
	byFP := map[string]normalize.Finding{}
	for _, f := range findings {
		byFP[f.Fingerprint] = f
	}
	best := byFP[fp(1)]
	testEntry := byFP[fp(2)]
	worst := byFP[fp(3)]
	if *best.Priority.Score <= *worst.Priority.Score {
		t.Fatalf("orden de puntuación inesperado: %d, %d", *best.Priority.Score, *worst.Priority.Score)
	}
	for _, want := range []string{"high", "kev", "epss_high", "reachable", "fix_available", "direct"} {
		if !contains(best.Priority.Factors, want) {
			t.Errorf("faltan factores %q en %v", want, best.Priority.Factors)
		}
	}
	if !contains(testEntry.Priority.Factors, "test_path") {
		t.Errorf("no se marcó la ruta de prueba: %v", testEntry.Priority.Factors)
	}
	if *testEntry.Priority.Score >= *best.Priority.Score {
		t.Errorf("la ruta de test no bajó la prioridad: %d vs %d", *testEntry.Priority.Score, *best.Priority.Score)
	}
	if best.Priority.Rank == nil || *best.Priority.Rank != 1 {
		t.Errorf("rank = %v", best.Priority.Rank)
	}
}

func TestActionsOrderAndContent(t *testing.T) {
	doc := &report.Document{
		Target: report.Target{Units: []report.UnitInfo{{ID: "backoffice", Path: "backoffice", Kind: "module"}}},
		Validation: report.Validation{
			Recipes:    []report.Recipe{},
			Unresolved: []report.Unresolved{{Unit: "backoffice", Missing: []string{"test", "build"}}},
		},
		Errors: []report.Error{{Code: "requirement_missing", Scope: "psalm:backoffice", Message: "falta composer install"}},
	}
	groups := []report.RemediationGroup{
		{ID: "rg-secret-x", Kind: "secret_rotation", Unit: "backoffice", Fixes: []string{fp(1)}},
		{ID: "rg-go-x", Kind: "dependency_upgrade", Unit: "backoffice", Fixes: []string{fp(2), fp(3)},
			Package: &report.GroupPackage{Ecosystem: "Go", Name: "x", From: "1", To: "2"}, BreakingRisk: "major",
			Commands: report.GroupCommands{Apply: "go get x@2", Origin: "cgc-scan"}},
	}
	got := Actions(doc, groups)
	if len(got) != 4 {
		t.Fatalf("acciones = %+v", got)
	}
	if got[0].Action != "confirm_recipes" || got[0].Command != "cgc-scan scan backoffice --confirm-recipes" {
		t.Errorf("primera acción = %+v", got[0])
	}
	if got[1].Action != "revoke_secret" || !got[1].UserRequired {
		t.Errorf("segunda acción = %+v", got[1])
	}
	if got[2].Action != "apply_group" || got[2].Fixes != 2 {
		t.Errorf("tercera acción = %+v", got[2])
	}
	if got[3].Action != "install_toolchain" || got[3].Tool != "composer install" {
		t.Errorf("cuarta acción = %+v", got[3])
	}
}

func ptr[T any](v T) *T { return &v }

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
