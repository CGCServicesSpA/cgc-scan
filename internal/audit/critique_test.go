package audit

import (
	"strings"
	"testing"
)

func webhookSurface() Uncovered {
	return Uncovered{
		Surface: "webhook", Domain: "code", Boundary: "trust", Subsystem: "root",
		AttackClass: "webhook-trust", StartingPaths: []string{"main.go"},
		Reason: "superficie no mapeada por el catálogo",
	}
}

// coveredAll asigna y cubre todas las unidades planificadas con un agente.
func coveredAll(t *testing.T, l *Ledger, c *Candidates, agent string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		task, err := Next(l, c, NextOptions{AgentID: agent, MaxUnits: 4})
		if err != nil {
			t.Fatalf("next %s: %v", agent, err)
		}
		if task.Kind != "hunt" {
			t.Fatalf("se esperaba caza, got %s", task.Kind)
		}
		if _, err := Submit(l, c, coveredSubmissionFor(agent, task)); err != nil {
			t.Fatalf("submit: %v", err)
		}
		if l.Summary.Planned == 0 && l.Summary.InProgress == 0 {
			return
		}
	}
	t.Fatal("el bucle de cobertura no terminó")
}

func coveredSubmissionFor(agent string, task *Task) *Submission {
	units := make([]UnitResult, 0, len(task.Units))
	for _, au := range task.Units {
		units = append(units, UnitResult{
			CoverageID:            au.Unit.CoverageID,
			Disposition:           DispositionCovered,
			ReviewedPaths:         au.Unit.StartingPaths,
			Checks:                checksForUnit(agent, au.Unit.StartingPaths),
			CandidateFingerprints: []string{},
			Unresolved:            []string{},
		})
	}
	return &Submission{SchemaVersion: SubmissionSchemaVersion, AgentID: agent, Units: units}
}

func checksForUnit(agent string, paths []string) []Check {
	checks := make([]Check, 0, len(paths))
	for _, p := range paths {
		checks = append(checks, Check{
			AgentID: agent, ReviewedPaths: []string{p},
			Invariant: "invariante comprobado", Method: "source", Result: "sin hallazgos",
		})
	}
	return checks
}

func TestCritiqueCycleAddsWorkAndClosesClean(t *testing.T) {
	l := standardLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	coveredAll(t, l, c, "hunter-a")

	// La ola completó: el crítico recibe su tarea.
	task, err := Next(l, c, NextOptions{AgentID: "critic-a"})
	if err != nil {
		t.Fatalf("next critique: %v", err)
	}
	if task.Kind != "critique" {
		t.Fatalf("tarea inesperada: %s", task.Kind)
	}
	if l.Critique == nil || !l.Critique.Pending || l.Critique.IssuedTo != "critic-a" || l.Critique.Rounds != 1 {
		t.Fatalf("estado de crítica inesperado: %+v", l.Critique)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}

	// Repetir next no emite otra crítica.
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != ErrNoTask {
		t.Fatalf("next repetido = %v, want ErrNoTask", err)
	}

	// El crítico declara una superficie omitida: genera trabajo.
	out, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a",
		Critique: &Critique{MissingUnits: []Uncovered{webhookSurface()}},
	})
	if err != nil {
		t.Fatalf("submit critique: %v", err)
	}
	if len(out.AddedUnits) != 1 {
		t.Fatalf("se esperaba una unidad añadida: %+v", out)
	}
	if l.Critique.FinalClean {
		t.Fatal("una crítica con trabajo nuevo no queda limpia")
	}

	// La superficie omitida se procesa y vuelve a crítica.
	coveredAll(t, l, c, "hunter-b")
	if l.Critique.Pending {
		t.Fatal("no debe haber crítica pendiente tras la caza")
	}
	task, err = Next(l, c, NextOptions{AgentID: "critic-a"})
	if err != nil || task.Kind != "critique" {
		t.Fatalf("next critique 2: %v %+v", err, task)
	}
	if l.Critique.Rounds != 2 {
		t.Fatalf("rounds = %d, want 2", l.Critique.Rounds)
	}

	// La crítica final limpia cierra el reparto y la corrida completa.
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a",
		Critique: &Critique{},
	}); err != nil {
		t.Fatalf("submit critique final: %v", err)
	}
	if !l.Critique.FinalClean {
		t.Fatal("la crítica final debe quedar limpia")
	}
	if _, err := BuildFindings(l, c); err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.RunStatus != StatusComplete {
		t.Fatalf("la corrida standard debe completarse con crítica limpia: %s/%s",
			l.RunStatus, l.IncompleteReason)
	}
}

func TestCritiqueRepeatedProposalDoesNotDuplicate(t *testing.T) {
	l := standardLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	coveredAll(t, l, c, "hunter-a")
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a",
		Critique: &Critique{MissingUnits: []Uncovered{webhookSurface()}},
	}); err != nil {
		t.Fatal(err)
	}
	total := l.Summary.UnitsTotal

	// La misma superficie repetida no duplica unidades.
	coveredAll(t, l, c, "hunter-a")
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a",
		Critique: &Critique{MissingUnits: []Uncovered{webhookSurface()}},
	}); err != nil {
		t.Fatal(err)
	}
	if l.Summary.UnitsTotal != total {
		t.Fatalf("la propuesta repetida duplicó unidades: %d != %d", l.Summary.UnitsTotal, total)
	}
}

func TestCritiqueStopDoesNotBypassPendingRequirements(t *testing.T) {
	l := standardLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	coveredAll(t, l, c, "hunter-a")
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != nil {
		t.Fatal(err)
	}

	// Un stop con trabajo nuevo aplica el trabajo y no queda limpia.
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a",
		Critique: &Critique{Stop: true, Reason: "no hay más superficies", MissingUnits: []Uncovered{webhookSurface()}},
	}); err != nil {
		t.Fatalf("submit stop con trabajo: %v", err)
	}
	if !l.Critique.Stopped {
		t.Fatal("el stop debe archivarse")
	}
	if l.Critique.FinalClean {
		t.Fatal("un stop con requisitos pendientes no queda limpio")
	}

	// El trabajo nuevo sigue pendiente: la corrida no se completa.
	coveredAll(t, l, c, "hunter-a")
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a",
		Critique: &Critique{Stop: true, Reason: "no hay más superficies"},
	}); err != nil {
		t.Fatalf("submit stop: %v", err)
	}
	if !l.Critique.FinalClean {
		t.Fatal("el stop sin requisitos pendientes queda limpio")
	}
	if _, err := BuildFindings(l, c); err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.RunStatus != StatusComplete {
		t.Fatalf("la corrida debe completarse: %s/%s", l.RunStatus, l.IncompleteReason)
	}
}

func TestCritiqueReassignArchivesAttempts(t *testing.T) {
	l := standardLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	coveredAll(t, l, c, "hunter-a")
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != nil {
		t.Fatal(err)
	}
	// El crítico reasigna una unidad cubierta con evidencia débil.
	target := l.Units[0].CoverageID
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a",
		Critique: &Critique{ReassignIDs: []string{target}},
	}); err != nil {
		t.Fatalf("submit reassign: %v", err)
	}
	unit := l.UnitByID(target)
	if unit.State != StatePlanned || unit.Owner != "" {
		t.Fatalf("la unidad debe volver a planned: %+v", unit)
	}
	if len(unit.Attempts) != 1 || unit.Attempts[0].State != StateCovered || len(unit.Attempts[0].Checks) != 1 {
		t.Fatalf("el intento debe archivarse con sus checks: %+v", unit.Attempts)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}

	// Otro agente recibe la unidad con la ola siguiente.
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-c", MaxUnits: 1}); err != nil {
		t.Fatal(err)
	}
	if unit.Wave != 2 || unit.Owner != "hunter-c" {
		t.Fatalf("reasignación inesperada: %+v", unit)
	}
}

func TestCritiqueIndependenceAndQuickNotRequired(t *testing.T) {
	// quick no emite crítica y rechaza su entrega.
	lq := plannerLedger("sql-injection")
	cq := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: lq.Run.ID, Items: []Candidate{}}
	coveredAll(t, lq, cq, "hunter-a")
	if _, err := Next(lq, cq, NextOptions{AgentID: "critic-a"}); err != ErrNoTask {
		t.Fatalf("quick no debe emitir crítica: %v", err)
	}
	if _, err := Submit(lq, cq, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a", Critique: &Critique{},
	}); err == nil || !strings.Contains(err.Error(), "no requiere crítica") {
		t.Fatalf("err = %v, want perfil sin crítica", err)
	}

	// El crítico con unidades en curso no puede entregar su crítica.
	l := standardLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	coveredAll(t, l, c, "hunter-a")
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != nil {
		t.Fatal(err)
	}
	// Un agente distinto no puede responder la crítica ajena.
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-b", Critique: &Critique{},
	}); err == nil || !strings.Contains(err.Error(), "es de") {
		t.Fatalf("err = %v, want crítica ajena", err)
	}
	// El propio crítico, con trabajo en curso, tampoco.
	l.UnitByID("root/code/sql-injection").State = StateInProgress
	l.UnitByID("root/code/sql-injection").Owner = "critic-a"
	l.Recompute()
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a", Critique: &Critique{},
	}); err == nil || !strings.Contains(err.Error(), "unidades en curso") {
		t.Fatalf("err = %v, want crítico con trabajo en curso", err)
	}
}
