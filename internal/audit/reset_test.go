package audit

import (
	"strings"
	"testing"
)

func TestResetUnitArchivesAbandonedAttempt(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next: %v", err)
	}
	unit := l.UnitByID("root/code/sql-injection")
	if unit.State != StateInProgress || unit.Owner != "hunter-a" || unit.Wave != 1 {
		t.Fatalf("unidad mal asignada: %+v", unit)
	}
	if err := ResetUnit(l, "root/code/sql-injection", "el agente abandonó la asignación"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if unit.State != StatePlanned || unit.Owner != "" {
		t.Fatalf("unidad no devuelta a planned: %+v", unit)
	}
	if len(unit.Attempts) != 1 {
		t.Fatalf("falta el intento archivado: %+v", unit.Attempts)
	}
	archived := unit.Attempts[0]
	if archived.AgentID != "hunter-a" || archived.State != StateBlocked || archived.Wave != 1 {
		t.Fatalf("intento mal archivado: %+v", archived)
	}
	if archived.Reason != "el agente abandonó la asignación" {
		t.Fatalf("razón no archivada: %+v", archived)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido tras el reset: %v", err)
	}

	// Un reinicio repetido no agrega historial falso.
	if err := ResetUnit(l, "root/code/sql-injection", "otra razón"); err == nil ||
		!strings.Contains(err.Error(), "solo in_progress") {
		t.Fatalf("err = %v, want unidad no elegible", err)
	}
	if len(unit.Attempts) != 1 {
		t.Fatalf("el reinicio repetido agregó historial: %+v", unit.Attempts)
	}

	// Otro agente recibe la unidad con la ola siguiente; el intento
	// archivado no contamina el estado vigente.
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-b", MaxUnits: 1}); err != nil {
		t.Fatalf("next tras reset: %v", err)
	}
	if unit.State != StateInProgress || unit.Owner != "hunter-b" || unit.Wave != 2 {
		t.Fatalf("reasignación inesperada: %+v", unit)
	}
	if len(unit.Checks) != 0 || len(unit.ReviewedPaths) != 0 {
		t.Fatalf("el intento archivado dejó evidencia vigente: %+v", unit)
	}
}

func TestResetUnitRejectsUnknownUnitAndEmptyReason(t *testing.T) {
	l := plannerLedger("sql-injection")
	if err := ResetUnit(l, "root/nope/x", "razón"); err == nil || !strings.Contains(err.Error(), "desconocido") {
		t.Fatalf("err = %v, want coverage_id desconocido", err)
	}
	if err := ResetUnit(l, "root/code/sql-injection", "   "); err == nil ||
		!strings.Contains(err.Error(), "razón") {
		t.Fatalf("err = %v, want razón exigida", err)
	}
	l.RunStatus = StatusComplete
	if err := ResetUnit(l, "root/code/sql-injection", "razón"); err == nil ||
		!strings.Contains(err.Error(), "no acepta reinicios") {
		t.Fatalf("err = %v, want corrida sellada", err)
	}
}
