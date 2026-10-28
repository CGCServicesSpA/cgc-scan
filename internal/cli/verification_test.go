package cli

import (
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func TestAttachVerificationPerFinding(t *testing.T) {
	doc := &report.Document{
		Run: report.Run{Arguments: map[string]any{"trivy_mode": "docker", "offline": true}},
		Target: report.Target{Units: []report.UnitInfo{
			{ID: "project", Path: ".", Kind: "repository"},
			{ID: "root", Path: ".", Kind: "module"},
			{ID: "svc", Path: "services/api", Kind: "module"},
		}},
		Validation: report.Validation{
			Recipes: []report.Recipe{
				{Unit: "root", Kind: "test", Command: "go test ./...", Workdir: ".", Origin: "user"},
				{Unit: "root", Kind: "build", Command: "go build ./...", Workdir: ".", Origin: "user"},
				{Unit: "svc", Kind: "test", Command: "npm test", Workdir: "services/api", Origin: "user"},
			},
			Unresolved: []report.Unresolved{{Unit: "svc", Missing: []string{"build"}}},
		},
		Findings: []normalize.Finding{
			{Fingerprint: strings.Repeat("a", 32), Locations: []normalize.Location{{Path: "go.mod"}}},
			{Fingerprint: strings.Repeat("b", 32), Locations: []normalize.Location{{Path: "services/api/package.json"}}},
			{Fingerprint: strings.Repeat("c", 32), Locations: []normalize.Location{{Path: "docs/leeme.md"}}},
		},
	}
	attachVerification(doc, nil)

	root := doc.Findings[0].Verification
	if root == nil || root.Unit != "root" || root.Status != "ready" {
		t.Fatalf("root = %+v", root)
	}
	if len(root.Recipes) != 2 {
		t.Fatalf("recetas root = %+v", root.Recipes)
	}
	if !strings.Contains(root.Rescan, "cgc-scan scan . --trivy-mode docker --offline --format json") {
		t.Fatalf("reescaneo root = %q", root.Rescan)
	}

	svc := doc.Findings[1].Verification
	if svc == nil || svc.Unit != "svc" || svc.Status != "blocked" {
		t.Fatalf("svc = %+v", svc)
	}
	if len(svc.Missing) != 1 || svc.Missing[0] != "build" {
		t.Fatalf("faltantes svc = %+v", svc.Missing)
	}
	if !strings.Contains(svc.Rescan, "cgc-scan scan services/api") {
		t.Fatalf("reescaneo svc = %q", svc.Rescan)
	}

	// El módulo raíz (".") cubre el archivo de documentación; su receta es la
	// que aplica al proyecto cuando no hay otra unidad más específica.
	rootDocs := doc.Findings[2].Verification
	if rootDocs == nil || rootDocs.Unit != "root" || rootDocs.Status != "ready" {
		t.Fatalf("rootDocs = %+v", rootDocs)
	}
}

func TestAttachVerificationFallsBackToProject(t *testing.T) {
	doc := &report.Document{
		Target: report.Target{Units: []report.UnitInfo{
			{ID: "project", Path: ".", Kind: "repository"},
			{ID: "svc", Path: "services/api", Kind: "module"},
		}},
		Findings: []normalize.Finding{
			{Fingerprint: strings.Repeat("a", 32), Locations: []normalize.Location{{Path: "README.md"}}},
		},
	}
	attachVerification(doc, nil)
	v := doc.Findings[0].Verification
	if v == nil || v.Unit != "project" || v.Status != "blocked" {
		t.Fatalf("project = %+v", v)
	}
}

func TestAttachVerificationHasRecipeForEveryVulnerability(t *testing.T) {
	// Aunque una unidad no tenga recetas, cada hallazgo lleva un objeto de
	// verificación bloqueado: nunca se omite la receta silenciosamente.
	doc := &report.Document{
		Target: report.Target{Units: []report.UnitInfo{{ID: "project", Path: ".", Kind: "repository"}}},
		Findings: []normalize.Finding{
			{Fingerprint: strings.Repeat("a", 32), Kind: normalize.KindVulnerability},
		},
	}
	attachVerification(doc, nil)
	v := doc.Findings[0].Verification
	if v == nil || v.Status != "blocked" || len(v.Missing) != 2 {
		t.Fatalf("verificación = %+v", v)
	}
}

func TestShellQuote(t *testing.T) {
	got := shellQuote("services/api con espacio")
	if got != "'services/api con espacio'" {
		t.Fatalf("quote = %q", got)
	}
	if shellQuote("services/api") != "services/api" {
		t.Fatal("no se evitó una cita innecesaria")
	}
}

func TestAttachVerificationIncludesUnconfirmedCandidates(t *testing.T) {
	doc := &report.Document{
		Target: report.Target{Units: []report.UnitInfo{{ID: "svc", Path: "svc", Kind: "module"}}},
		Findings: []normalize.Finding{
			{Fingerprint: strings.Repeat("e", 32), Locations: []normalize.Location{{Path: "svc/go.mod"}}},
		},
	}
	suggested := map[string][]normalize.VerificationRecipe{
		"svc": {{Unit: "svc", Kind: "test", Command: "go test ./...", Workdir: "svc", Origin: "candidate"}},
	}
	attachVerification(doc, suggested)
	v := doc.Findings[0].Verification
	if v == nil || v.Status != "blocked" {
		t.Fatalf("verificación = %+v", v)
	}
	if len(v.Suggested) != 1 || v.Suggested[0].Origin != "candidate" {
		t.Fatalf("sugerencias = %+v", v.Suggested)
	}
	if !strings.Contains(v.Note, "sugerencias detectadas") {
		t.Fatalf("nota = %q", v.Note)
	}
}
