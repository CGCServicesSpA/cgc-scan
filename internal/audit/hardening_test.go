package audit

import (
	"strings"
	"testing"
)

func TestHardeningByUnitStaysInTargetUnit(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 2})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, au := range task.Units {
		ids = append(ids, au.Unit.CoverageID)
	}
	sub := coveredSubmissionFor("hunter-a", task)
	sub.HardeningByUnit = []UnitHardening{
		{CoverageID: ids[0], Note: "fijar permisos del directorio de caché"},
	}
	if _, err := Submit(l, c, sub); err != nil {
		t.Fatal(err)
	}
	// La recomendación dirigida no se propaga a las demás unidades.
	if got := l.UnitByID(ids[0]).Hardening; len(got) != 1 || got[0] != "fijar permisos del directorio de caché" {
		t.Fatalf("unidad objetivo: %+v", got)
	}
	if got := l.UnitByID(ids[1]).Hardening; len(got) != 0 {
		t.Fatalf("la recomendación se propagó a otra unidad: %+v", got)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestHardeningGlobalLegacySemanticsPreserved(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 2})
	if err != nil {
		t.Fatal(err)
	}
	// Formato antiguo: el campo global se aplica a todas las unidades
	// entregadas, sin reinterpretación.
	sub := coveredSubmissionFor("hunter-a", task)
	sub.Hardening = []string{"revisar la política de timeouts"}
	if _, err := Submit(l, c, sub); err != nil {
		t.Fatal(err)
	}
	for _, au := range task.Units {
		got := l.UnitByID(au.Unit.CoverageID).Hardening
		if len(got) != 1 || got[0] != "revisar la política de timeouts" {
			t.Fatalf("semántica global perdida en %s: %+v", au.Unit.CoverageID, got)
		}
	}
}

func TestHardeningMixedFormatsCoexist(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 2})
	if err != nil {
		t.Fatal(err)
	}
	target := task.Units[0].Unit.CoverageID
	other := task.Units[1].Unit.CoverageID
	sub := coveredSubmissionFor("hunter-a", task)
	sub.Hardening = []string{"nota global"}
	sub.HardeningByUnit = []UnitHardening{{CoverageID: target, Note: "nota dirigida"}}
	if _, err := Submit(l, c, sub); err != nil {
		t.Fatal(err)
	}
	// La unidad objetivo acumula global + dirigida; la otra solo global.
	if got := l.UnitByID(target).Hardening; len(got) != 2 || got[0] != "nota global" || got[1] != "nota dirigida" {
		t.Fatalf("formato mixto en la objetivo: %+v", got)
	}
	if got := l.UnitByID(other).Hardening; len(got) != 1 || got[0] != "nota global" {
		t.Fatalf("formato mixto en la no objetivo: %+v", got)
	}
}

func TestHardeningByUnitRejectsForeignUnitWithoutSideEffects(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 2})
	if err != nil {
		t.Fatal(err)
	}
	sub := coveredSubmissionFor("hunter-a", task)
	sub.HardeningByUnit = []UnitHardening{{CoverageID: "root/code/ajena", Note: "nota"}}
	before, err := l.JSON()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Submit(l, c, sub)
	if err == nil || !strings.Contains(err.Error(), "no pertenece a la entrega") {
		t.Fatalf("err = %v, want unidad ajena rechazada", err)
	}
	after, _ := l.JSON()
	if string(before) != string(after) {
		t.Fatal("el rechazo mutó el ledger")
	}

	// Nota vacía también se rechaza.
	sub2 := coveredSubmissionFor("hunter-a", task)
	sub2.HardeningByUnit = []UnitHardening{{CoverageID: task.Units[0].Unit.CoverageID, Note: "   "}}
	if _, err := Submit(l, c, sub2); err == nil || !strings.Contains(err.Error(), "no vacía") {
		t.Fatalf("err = %v, want nota vacía rechazada", err)
	}
}
