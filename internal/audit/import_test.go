package audit

import (
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

func importedFinding(fp, engine, unit string, missing []string, rescan string) normalize.Finding {
	f := normalize.Finding{
		Fingerprint: fp,
		Kind:        normalize.KindCode,
		Title:       "Fuga de entrada en el handler",
		Descriptions: []normalize.Description{{
			Text:   "La entrada del usuario alcanza el proceso sin validación.",
			Source: "semgrep",
		}},
		Severity: normalize.SeverityInfo{
			Original:   "critical",
			Normalized: "critical",
			Source:     "semgrep",
		},
		Locations: []normalize.Location{{
			Path:      "main.go",
			StartLine: intPtr(3),
		}},
	}
	f.Sources = []normalize.SourceRef{{Engine: engine, Rule: "rule-1"}}
	f.Verification = &normalize.Verification{
		Unit:    unit,
		Status:  "blocked",
		Missing: missing,
		Rescan:  rescan,
	}
	return f
}

func intPtr(n int) *int { return &n }

func importDocument(findings ...normalize.Finding) *report.Document {
	return &report.Document{
		SchemaVersion: version.SchemaVersion,
		Findings:      findings,
	}
}

func TestImportLeadsCreatesPlannedUnitsNeverConfirmed(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	doc := importDocument(importedFinding("fp-eng-1", "semgrep", "go-audit", []string{"falta un despliegue local"}, "reescanear con semgrep"))

	out, leads, err := ImportLeads(l, c, doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(out.AddedUnits) != 1 || len(out.Proposed) != 1 {
		t.Fatalf("resultado inesperado: %+v", out)
	}
	unit := l.UnitByID(out.AddedUnits[0])
	if unit == nil || unit.State != StatePlanned {
		t.Fatalf("lead no planificado: %+v", unit)
	}
	if !strings.HasPrefix(unit.CoverageID, "import/") {
		t.Fatalf("coverage_id inesperado: %s", unit.CoverageID)
	}
	if unit.Domain != "import" {
		t.Fatalf("el dominio del lead debe ser import: %+v", unit)
	}

	// El veredicto propuesto es needs_validation: nunca confirmado.
	cand := c.CandidateByFingerprint("fp-eng-1")
	if cand == nil || cand.Proposed.Verdict != VerdictNeedsValidation {
		t.Fatalf("el hallazgo importado no puede aparecer como confirmado: %+v", cand)
	}
	if cand.State != CandidatePending {
		t.Fatalf("el candidato debe esperar verificación: %+v", cand.State)
	}
	// La severidad del motor no se convierte en severidad auditada.
	if cand.Proposed.Severity != nil {
		t.Fatalf("un needs_validation no lleva severidad: %+v", cand.Proposed.Severity)
	}
	if len(leads) != 1 || leads[0].Engine != "semgrep" {
		t.Fatalf("procedencia inesperada: %+v", leads)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("candidatos inválidos: %v", err)
	}
}

func TestImportLeadsTwiceIsIdempotent(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	doc := importDocument(importedFinding("fp-eng-1", "semgrep", "go-audit", []string{"falta un despliegue local"}, "reescanear"))

	if _, _, err := ImportLeads(l, c, doc); err != nil {
		t.Fatal(err)
	}
	total := l.Summary.UnitsTotal
	pending := len(c.Items)

	out, _, err := ImportLeads(l, c, doc)
	if err != nil {
		t.Fatalf("import repetido: %v", err)
	}
	if len(out.AddedUnits) != 0 || len(out.Proposed) != 0 {
		t.Fatalf("la importación repetida duplicó trabajo: %+v", out)
	}
	if l.Summary.UnitsTotal != total || len(c.Items) != pending {
		t.Fatalf("el trabajo pendiente cambió: %d != %d", l.Summary.UnitsTotal, total)
	}
}

func TestImportLeadsRequiresSatisfiableContract(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	// Sin bloqueos ni plan: solo lead, sin veredicto.
	doc := importDocument(importedFinding("fp-ready", "semgrep", "go-audit", nil, ""))
	out, leads, err := ImportLeads(l, c, doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Proposed) != 0 || len(out.AddedUnits) != 1 {
		t.Fatalf("un hallazgo sin contrato de veredicto no se propone: %+v", out)
	}
	if c.CandidateByFingerprint("fp-ready") != nil {
		t.Fatal("no debe crearse candidato sin contrato satisfacible")
	}
	if len(leads) != 1 {
		t.Fatalf("el lead se archiva igualmente: %+v", leads)
	}
}

func TestImportLeadsRejectsIncompatibleReport(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	doc := importDocument(importedFinding("fp-eng-1", "semgrep", "go-audit", []string{"x"}, "rescan"))
	doc.SchemaVersion = "9.9.9"
	if _, _, err := ImportLeads(l, c, doc); err == nil || !strings.Contains(err.Error(), "esquema") {
		t.Fatalf("err = %v, want rechazo de versión incompatible", err)
	}
}
