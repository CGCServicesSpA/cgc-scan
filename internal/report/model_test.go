package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
)

func minimalDoc() *Document {
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	return &Document{
		SchemaVersion: "1.0.0",
		Run:           NewRun("run-1", start, time.Second, map[string]any{"format": "json"}),
		Target: Target{
			Root: "/tmp/p", LocalID: LocalID("/tmp/p"),
			VCS: VCS{Available: false},
		},
		Coverage: Coverage{
			Partial: false,
			Scope:   Scope{Root: "/tmp/p"},
			Units:   []UnitCoverage{},
		},
		Tools:      Tools{Engines: []EngineReport{}},
		Isolation:  Isolation{Level: "configured", VerifiedBy: ""},
		Validation: Validation{},
		Policy:     Policy{FailOn: "high", UnknownCounts: true},
	}
}

func TestDocumentNormalizeAndValidate(t *testing.T) {
	doc := minimalDoc()
	doc.Normalize()
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("el documento mínimo no valida: %v", err)
	}
}

func TestDocumentListsAreNeverNull(t *testing.T) {
	doc := minimalDoc()
	data, err := RenderJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, forbidden := range []string{`"findings": null`, `"errors": null`, `"exclusions": null`, `"units": null`} {
		if strings.Contains(s, forbidden) {
			t.Errorf("el JSON contiene %s", forbidden)
		}
	}
}

func TestEmitTextMentionsCoverageAndIncomplete(t *testing.T) {
	doc := minimalDoc()
	doc.Coverage.Partial = true
	doc.Coverage.NotAnalyzed = []NotAnalyzedReport{{Unit: "svc", Path: "svc", Reason: "fuera de --include"}}
	doc.Errors = []Error{{Code: "engine_failed", Scope: "trivy:svc", Message: "boom"}}
	var buf bytes.Buffer
	if err := Emit(&buf, doc, "text"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Cobertura: PARCIAL", "No analizado: 1", "engine_failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("la salida de texto no contiene %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Error("la salida sin TTY contiene ANSI")
	}
}

func TestEmitJSONIsOnlyTheDocument(t *testing.T) {
	doc := minimalDoc()
	var buf bytes.Buffer
	if err := Emit(&buf, doc, "json"); err != nil {
		t.Fatal(err)
	}
	if err := Validate(buf.Bytes()); err != nil {
		t.Fatalf("la salida de Emit no valida: %v", err)
	}
	if strings.Contains(buf.String(), "level=") {
		t.Error("la salida JSON contiene logs")
	}
}

func TestEmitPromptPending(t *testing.T) {
	var buf bytes.Buffer
	if err := Emit(&buf, minimalDoc(), "prompt"); err == nil {
		t.Fatal("el prompt no debe fingir estar implementado antes de H5")
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	if _, err := Decode([]byte(`{"schema_version":"1.0.0","extra":1}`)); err == nil {
		t.Fatal("se aceptó un campo desconocido")
	}
}

func TestEmptyProjectUnitValidates(t *testing.T) {
	doc := minimalDoc()
	doc.Target.Units = []UnitInfo{{ID: "project", Path: ".", Kind: "repository"}}
	doc.Coverage.Units = []UnitCoverage{{ID: "project", Path: ".", Status: "completed", Engines: []EngineState{{ID: "trivy", Status: "completed"}}}}
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("una unidad sin lenguajes debe serializarse como [] y validar: %v", err)
	}
	data, _ := RenderJSON(doc)
	if strings.Contains(string(data), `"languages": null`) {
		t.Fatal("languages se serializó como null")
	}
}

func TestFindingOrderIsStable(t *testing.T) {
	doc := minimalDoc()
	low := normalize.Finding{Fingerprint: strings.Repeat("b", 32), Kind: normalize.KindCode, Title: "b", Severity: normalize.SeverityInfo{Normalized: normalize.SeverityLow, Source: "x"}, Sources: []normalize.SourceRef{{Engine: "x"}}}
	high := normalize.Finding{Fingerprint: strings.Repeat("a", 32), Kind: normalize.KindCode, Title: "a", Severity: normalize.SeverityInfo{Normalized: normalize.SeverityHigh, Source: "x"}, Sources: []normalize.SourceRef{{Engine: "x"}}}
	doc.Findings = []normalize.Finding{low, high}
	doc.Normalize()
	if doc.Findings[0].Fingerprint != strings.Repeat("a", 32) {
		t.Fatalf("orden = %v", doc.Findings)
	}
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("documento con hallazgos no valida: %v", err)
	}
}

func TestRenderTextShowsFixDescriptionAndReferences(t *testing.T) {
	doc := minimalDoc()
	doc.Findings = []normalize.Finding{{
		Fingerprint: strings.Repeat("a", 32),
		Kind:        normalize.KindVulnerability,
		Title:       "CVE en dependencia",
		Severity:    normalize.SeverityInfo{Original: "HIGH", Normalized: normalize.SeverityHigh, Source: "trivy"},
		Package: &normalize.PackageRef{
			Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.0", FixedVersion: strptr("v0.41.0"),
		},
		IDs:          []normalize.Identifier{{Type: "CVE", Value: "CVE-2026-0001"}, {Type: "CWE", Value: "CWE-787"}},
		Descriptions: []normalize.Description{{Text: "Una descripción útil de la vulnerabilidad.", Source: "trivy"}},
		Remediation:  []normalize.Remediation{{Description: "Actualizar a v0.41.0", Source: "advisory"}},
		References:   []string{"https://example.test/CVE-2026-0001"},
		Verification: &normalize.Verification{
			Unit: "root", Status: "ready",
			Recipes: []normalize.VerificationRecipe{
				{Unit: "root", Kind: "test", Command: "go test ./...", Workdir: ".", Origin: "user"},
				{Unit: "root", Kind: "build", Command: "go build ./...", Workdir: ".", Origin: "user"},
			},
			Suggested: []normalize.VerificationRecipe{
				{Unit: "root", Kind: "test", Command: "go test ./...", Workdir: ".", Origin: "candidate"},
			},
			Missing: []string{},
			Rescan:  "cgc-scan scan . --format json",
		},
		Locations: []normalize.Location{{Path: "go.mod"}},
		Sources:   []normalize.SourceRef{{Engine: "trivy", Version: "0.76.1"}},
		Policy:    normalize.FindingPolicy{Status: "active"},
	}}
	doc.Normalize()
	out := RenderText(doc)
	for _, want := range []string{
		"version corregida v0.41.0", "descripcion: Una descripción útil",
		"remediacion: Actualizar a v0.41.0", "referencias: https://example.test/CVE-2026-0001",
		"ids: CVE-2026-0001, CWE-787", "correcciones disponibles: 1",
		"validacion: lista", "receta test: `go test ./...` en . (user)",
		"receta build: `go build ./...` en . (user)", "reescaneo: `cgc-scan scan . --format json`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("la salida no contiene %q:\n%s", want, out)
		}
	}
}

func TestRenderTextMarksTruncatedDescription(t *testing.T) {
	doc := minimalDoc()
	doc.Findings = []normalize.Finding{{
		Fingerprint:  strings.Repeat("b", 32),
		Kind:         normalize.KindCode,
		Title:        "hallazgo",
		Severity:     normalize.SeverityInfo{Original: "error", Normalized: normalize.SeverityHigh, Source: "eslint"},
		Descriptions: []normalize.Description{{Text: strings.Repeat("x", 2000), Source: "eslint"}},
		Sources:      []normalize.SourceRef{{Engine: "eslint"}},
		Policy:       normalize.FindingPolicy{Status: "active"},
	}}
	doc.Normalize()
	out := RenderText(doc)
	if !strings.Contains(out, "texto truncado") || !strings.Contains(out, "consulta el reporte JSON") {
		t.Fatalf("no se marcó el truncamiento:\n%s", out)
	}
}

func TestFindingWithReferencesAndFixValidates(t *testing.T) {
	doc := minimalDoc()
	doc.Findings = []normalize.Finding{{
		Fingerprint:  strings.Repeat("c", 32),
		Kind:         normalize.KindVulnerability,
		Title:        "CVE con corrección",
		Severity:     normalize.SeverityInfo{Original: "HIGH", Normalized: normalize.SeverityHigh, Source: "trivy"},
		Package:      &normalize.PackageRef{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.0", FixedVersion: strptr("v0.41.0")},
		Descriptions: []normalize.Description{{Text: "descripción", Source: "trivy"}},
		References:   []string{"https://pkg.go.dev/vuln/GO-2026-6629"},
		Remediation:  []normalize.Remediation{{Description: "Actualizar a v0.41.0", Source: "advisory"}},
		Sources:      []normalize.SourceRef{{Engine: "trivy", Version: "0.76.1"}},
		Policy:       normalize.FindingPolicy{Status: "active"},
	}}
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("el hallazgo enriquecido no valida: %v", err)
	}
}

func TestFindingVerificationValidates(t *testing.T) {
	doc := minimalDoc()
	doc.Findings = []normalize.Finding{{
		Fingerprint: strings.Repeat("d", 32),
		Kind:        normalize.KindVulnerability,
		Title:       "CVE con receta",
		Severity:    normalize.SeverityInfo{Original: "HIGH", Normalized: normalize.SeverityHigh, Source: "trivy"},
		Package:     &normalize.PackageRef{Ecosystem: "Go", Name: "x/text", Version: "v0.3.0", FixedVersion: strptr("v0.41.0")},
		Sources:     []normalize.SourceRef{{Engine: "trivy"}},
		Verification: &normalize.Verification{
			Unit: "root", Status: "ready",
			Recipes: []normalize.VerificationRecipe{
				{Unit: "root", Kind: "test", Command: "go test ./...", Workdir: ".", Origin: "user"},
				{Unit: "root", Kind: "build", Command: "go build ./...", Workdir: ".", Origin: "user"},
			},
			Suggested: []normalize.VerificationRecipe{
				{Unit: "root", Kind: "test", Command: "go test ./...", Workdir: ".", Origin: "candidate"},
			},
			Missing: []string{},
			Rescan:  "cgc-scan scan . --format json",
		},
		Policy: normalize.FindingPolicy{Status: "active"},
	}}
	if err := ValidateDocument(doc); err != nil {
		t.Fatalf("la verificación por hallazgo no valida: %v", err)
	}
}
