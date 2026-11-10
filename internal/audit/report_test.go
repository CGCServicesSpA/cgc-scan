package audit

import (
	"strings"
	"testing"
)

func sealedFixture(t *testing.T) (*Ledger, *Candidates) {
	t.Helper()
	l := plannerLedger("sql-injection", "command-injection")
	l.Units[0].State = StateCandidate
	l.Units[0].Owner = "hunter-a"
	l.Units[0].ReviewedPaths = []string{"main.go"}
	l.Units[0].Checks = []Check{huntCheck("hunter-a")}
	l.Units[0].Candidates = []string{"fp-1"}
	l.Units[0].Hardening = []string{"fijar permisos del directorio de caché"}

	l.Units[1].State = StateCandidate
	l.Units[1].Owner = "hunter-b"
	l.Units[1].ReviewedPaths = []string{"main.go"}
	l.Units[1].Checks = []Check{huntCheck("hunter-b")}
	l.Units[1].Candidates = []string{"fp-2"}
	l.Recompute()

	medium := recordFor("fp-1", VerdictConfirmed)
	medium.Severity = &Severity{
		Likelihood: Score{Score: "medium", Reason: "requiere autenticación"},
		Impact:     Score{Score: "medium", Reason: "lectura limitada"},
		Overall:    "medium",
	}
	low := recordFor("fp-2", VerdictConfirmed)
	low.Severity = &Severity{
		Likelihood: Score{Score: "low", Reason: "requiere acceso local"},
		Impact:     Score{Score: "low", Reason: "divulgación mínima"},
		Overall:    "low",
	}
	nv := recordFor("fp-3", VerdictNeedsValidation)

	decided := func(fp string, record Record) Candidate {
		rec := record
		return Candidate{
			Fingerprint: fp,
			Unit:        "root/code/sql-injection",
			HunterAgent: "hunter-a",
			Proposed:    record,
			State:       CandidateDecided,
			Final:       &rec,
			Attempts:    []VerificationAttempt{},
		}
	}
	c := &Candidates{
		SchemaVersion: CandidatesSchemaVersion,
		RunID:         l.Run.ID,
		Items: []Candidate{
			decided("fp-1", medium),
			decided("fp-2", low),
			decided("fp-3", nv),
		},
	}
	// fp-2 y fp-3 pertenecen a la segunda unidad para que reconcile cuadre.
	l.Units[1].Candidates = []string{"fp-2", "fp-3"}
	l.Recompute()
	c.Normalize()
	return l, c
}

func TestBuildFindingsSealsComplete(t *testing.T) {
	l, c := sealedFixture(t)
	f, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.RunStatus != StatusComplete || l.IncompleteReason != "" {
		t.Fatalf("estado = %s/%s, want complete", l.RunStatus, l.IncompleteReason)
	}
	if f.Summary.Confirmed != 2 || f.Summary.NeedsValidation != 1 {
		t.Fatalf("resumen inesperado: %+v", f.Summary)
	}
	if f.Provenance.EngineVerified {
		t.Fatal("el motor no puede declararse verificador")
	}
	data := mustJSON(t, f)
	if err := ValidateFindings(data); err != nil {
		t.Fatalf("esquema: %v", err)
	}
}

func TestBuildFindingsIncompleteWithPendingCandidate(t *testing.T) {
	l, c := sealedFixture(t)
	c.Items[0].State = CandidatePending
	c.Items[0].Final = nil
	f, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.RunStatus != StatusIncomplete || l.IncompleteReason != IncompleteUnverifiedCandidates {
		t.Fatalf("estado = %s/%s", l.RunStatus, l.IncompleteReason)
	}
	for _, r := range f.Findings {
		if r.Fingerprint == "fp-1" {
			t.Fatal("un candidato sin veredicto final no puede entrar a findings.json")
		}
	}
}

func TestBuildFindingsIncompleteWithPlannedUnits(t *testing.T) {
	l, c := sealedFixture(t)
	l.Units = append(l.Units, Unit{
		CoverageID: "root/secrets/secret-in-tree", Subsystem: "root", Domain: "secrets",
		Boundary: "credential-exposure", AttackClass: "secret-in-tree",
		StartingPaths: []string{"main.go"}, State: StatePlanned,
		ReviewedPaths: []string{}, Checks: []Check{}, Candidates: []string{},
		Unresolved: []string{}, Attempts: []Attempt{},
	})
	l.Recompute()
	_, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.RunStatus != StatusIncomplete || l.IncompleteReason != IncompleteUnassigned {
		t.Fatalf("estado = %s/%s", l.RunStatus, l.IncompleteReason)
	}
}

func TestBuildFindingsRejectsDanglingCandidate(t *testing.T) {
	l, c := sealedFixture(t)
	c.Items = c.Items[:2]
	l.Units[1].Candidates = []string{"fp-2", "fp-3"}
	l.Recompute()
	_, err := BuildFindings(l, c)
	if err == nil || !strings.Contains(err.Error(), "sin estado de verificación") {
		t.Fatalf("se esperaba error de candidato huérfano, got %v", err)
	}
}

func TestRenderReport(t *testing.T) {
	l, c := sealedFixture(t)
	f, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	report := string(RenderReport(l, f))
	for _, want := range []string{
		"# Informe de auditoría",
		"el motor no ejecutó código del proyecto",
		"## Hallazgos confirmados",
		"## Necesita validación",
		"## Notas de endurecimiento",
		"fijar permisos del directorio de caché",
		"no tienen severidad",
		"## Cobertura",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("el informe no contiene %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, "fp-1") || strings.Contains(report, "fp-2") {
		t.Fatalf("el informe no debe exponer fingerprints internos:\n%s", report)
	}
	if again := string(RenderReport(l, f)); again != report {
		t.Fatal("el informe no es determinista")
	}
}

func TestRenderReportIncompleteIsExplicit(t *testing.T) {
	l, c := sealedFixture(t)
	c.Items[0].State = CandidatePending
	c.Items[0].Final = nil
	f, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	report := string(RenderReport(l, f))
	if !strings.Contains(report, "Corrida incompleta") || !strings.Contains(report, IncompleteUnverifiedCandidates) {
		t.Fatalf("el informe debe declarar la corrida incompleta:\n%s", report)
	}
	if !strings.Contains(report, "Este informe es parcial") {
		t.Fatalf("el informe debe declarar parcialidad:\n%s", report)
	}
}

func TestRenderFindingsDetailOnlyMediumAndAbove(t *testing.T) {
	l, c := sealedFixture(t)
	f, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	detail := string(RenderFindingsDetail(l, f))
	if !strings.Contains(detail, "Ejecución de comandos desde entrada no confiable") {
		t.Fatalf("falta el hallazgo medium:\n%s", detail)
	}
	if strings.Contains(detail, "fp-2") {
		t.Fatalf("no debe listar fingerprints:\n%s", detail)
	}
	if countHeadings(detail, "## ") != 1 {
		t.Fatalf("el detalle debe incluir solo el confirmado medium:\n%s", detail)
	}
}

func TestRenderNeedsValidationHasNoSeverity(t *testing.T) {
	l, c := sealedFixture(t)
	f, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	nv := string(RenderNeedsValidation(f))
	if !strings.Contains(nv, "No son vulnerabilidades confirmadas y no llevan severidad") {
		t.Fatalf("falta la declaración de veredicto:\n%s", nv)
	}
	if !strings.Contains(nv, "reproducir con un fixture mínimo") {
		t.Fatalf("falta el plan local:\n%s", nv)
	}
	if strings.Contains(strings.ToLower(nv), "severidad:") {
		t.Fatalf("un needs_validation no puede mostrar severidad:\n%s", nv)
	}
}

func countHeadings(s, prefix string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, prefix) {
			n++
		}
	}
	return n
}
