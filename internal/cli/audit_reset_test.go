package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
)

// taskUnitOf devuelve la unidad vigente del ledger para construir entregas.
func taskUnitOf(t *testing.T, runDir, unitID string) audit.Unit {
	t.Helper()
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	u := st.Ledger.UnitByID(unitID)
	if u == nil {
		t.Fatalf("unidad %s inexistente", unitID)
	}
	return *u
}

func TestAuditResetUnitRecoversAbandonedUnit(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "hunter-a", "--max-units", "1", "--format", "json"); code != 0 {
		t.Fatalf("next = %d: %s %s", code, out, errOut)
	}
	unitID := firstUnitID(t, runDir)
	if code, out, errOut := auditRun(t, app, "audit", "reset-unit", "--out", runDir,
		"--coverage-id", unitID, "--reason", "el agente abandonó la corrida"); code != 0 {
		t.Fatalf("reset-unit = %d: %s %s", code, out, errOut)
	}

	// Otro agente recibe la unidad con la ola siguiente.
	if code, out, errOut := auditRun(t, app, "audit", "next", "--out", runDir,
		"--agent", "hunter-b", "--max-units", "1", "--format", "json"); code != 0 {
		t.Fatalf("next hunter-b = %d: %s %s", code, out, errOut)
	}
	reassigned := firstUnitID(t, runDir)
	if reassigned != unitID {
		t.Fatalf("la unidad no se reasignó: %s != %s", reassigned, unitID)
	}

	// Una entrega tardía del intento abandonado se rechaza.
	late := coveredSubmission("hunter-a", audit.Task{Units: []audit.AssignmentUnit{{
		Unit:  taskUnitOf(t, runDir, unitID),
		Class: audit.Class{},
	}}})
	if code, _, errOut := auditRun(t, app, "audit", "submit", "--out", runDir,
		"--file", writeSubmissionFile(t, late)); code != 3 || !strings.Contains(errOut, "pertenece") {
		t.Fatalf("entrega tardía = %d: %s; se esperaba rechazo por dueño", code, errOut)
	}

	// La entrega del nuevo dueño aplica y el historial queda intacto.
	task := audit.Task{Units: []audit.AssignmentUnit{{Unit: taskUnitOf(t, runDir, unitID)}}}
	if code, out, errOut := auditRun(t, app, "audit", "submit", "--out", runDir,
		"--file", writeSubmissionFile(t, coveredSubmission("hunter-b", task))); code != 0 {
		t.Fatalf("submit hunter-b = %d: %s %s", code, out, errOut)
	}
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	u := st.Ledger.UnitByID(unitID)
	if u.State != audit.StateCovered || u.Owner != "hunter-b" || u.Wave != 2 {
		t.Fatalf("unidad final inesperada: %+v", u)
	}
	if len(u.Attempts) != 1 || u.Attempts[0].AgentID != "hunter-a" || u.Attempts[0].State != audit.StateBlocked {
		t.Fatalf("historial inesperado: %+v", u.Attempts)
	}
	if err := audit.ValidateLedgerSemantics(st.Ledger); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestAuditResetUnitRejectsBadInput(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	if code, _, _ := auditRun(t, app, "audit", "reset-unit", "--out", runDir,
		"--coverage-id", "root/code/x"); code != 2 {
		t.Fatalf("sin razón = %d, want 2", code)
	}
	if code, _, errOut := auditRun(t, app, "audit", "reset-unit", "--out", runDir,
		"--coverage-id", "root/nope/x", "--reason", "razón"); code != 3 ||
		!strings.Contains(errOut, "desconocido") {
		t.Fatalf("unidad desconocida = %d: %s; want 3 con diagnóstico", code, errOut)
	}
}
