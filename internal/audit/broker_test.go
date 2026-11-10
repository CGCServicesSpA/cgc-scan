package audit

import (
	"strings"
	"testing"
)

func plannerLedger(ids ...string) *Ledger {
	units := make([]Unit, 0, len(ids))
	for _, id := range ids {
		units = append(units, Unit{
			CoverageID:    "root/code/" + id,
			Subsystem:     "root",
			Domain:        "code",
			Boundary:      "input-to-sink",
			AttackClass:   id,
			StartingPaths: []string{"main.go"},
			State:         StatePlanned,
			ReviewedPaths: []string{},
			Checks:        []Check{},
			Candidates:    []string{},
			Unresolved:    []string{},
			Attempts:      []Attempt{},
		})
	}
	l := &Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Run:           Run{ID: "run-1", StartedAt: "2026-11-09T00:00:00Z", CLIVersion: "test", SourceRef: "rev-1"},
		Target:        Target{Root: "/tmp/p", LocalID: "p"},
		// quick: una pasada de verificación; los tests de dos pasadas fijan
		// el perfil explícitamente.
		Profile:   ProfileQuick,
		Budget:    &Budget{MaxAgentInvocations: 10},
		RunStatus: StatusInProgress,
		Units:     units,
	}
	l.Recompute()
	return l
}

func emptyCandidates() *Candidates {
	return &Candidates{SchemaVersion: CandidatesSchemaVersion, Items: []Candidate{}}
}

func huntCheck(agent string) Check {
	return Check{
		AgentID: agent, ReviewedPaths: []string{"main.go"},
		Invariant: "la entrada se valida antes del sink", Method: "source", Result: "no hay control",
	}
}

func huntSubmission(agent, unitID, disposition string, fps ...string) *Submission {
	return &Submission{
		SchemaVersion: SubmissionSchemaVersion,
		AgentID:       agent,
		Units: []UnitResult{{
			CoverageID:            unitID,
			Disposition:           disposition,
			ReviewedPaths:         []string{"main.go"},
			Checks:                []Check{huntCheck(agent)},
			CandidateFingerprints: fps,
			Unresolved:            []string{},
		}},
	}
}

func recordFor(fp, verdict string) Record {
	base := validFindings().Findings[0]
	base.Fingerprint = fp
	base.Verdict = verdict
	if verdict == VerdictRejected {
		return Record{
			Verdict: VerdictRejected, Fingerprint: fp,
			Title: "t", Description: "d", ClaimedRootCause: "c",
			Trace: base.Trace, Evidence: base.Evidence,
			Reason: "la capa visible impide el efecto",
		}
	}
	if verdict == VerdictNeedsValidation {
		return Record{
			Verdict: VerdictNeedsValidation, Fingerprint: fp,
			Title: "t", Description: "d", ClaimedRootCause: "c",
			Trace: base.Trace, Evidence: base.Evidence,
			Blockers:       []string{"falta una configuración de despliegue"},
			ValidationPlan: &ValidationPlan{Local: "reproducir con un fixture mínimo"},
		}
	}
	return base
}

func TestNextAssignsRelatedUnitsWithOneBudgetedInvocation(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	l := plannerLedger("sql-injection", "command-injection", "weak-crypto")
	task, err := Next(l, emptyCandidates(), NextOptions{AgentID: "hunter-a", Catalog: cat, MaxUnits: 2})
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if task.Kind != "hunt" || len(task.Units) != 2 {
		t.Fatalf("tarea inesperada: %+v", task)
	}
	if l.Budget.Used != 1 {
		t.Fatalf("used = %d, want 1", l.Budget.Used)
	}
	for _, u := range task.Units {
		if u.Unit.State != StateInProgress || u.Unit.Owner != "hunter-a" || u.Unit.Wave != 1 {
			t.Fatalf("unidad no asignada correctamente: %+v", u.Unit)
		}
		if u.Class.Invariant == "" {
			t.Fatalf("la asignación no incluye el invariante de la clase")
		}
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido tras repartir: %v", err)
	}
}

func TestNextPrefersVerificationAndRejectsHunter(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := emptyCandidates()
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next hunt: %v", err)
	}
	if _, err := Submit(l, c, func() *Submission {
		s := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCandidate, "fp-1")
		s.Candidates = []Record{recordFor("fp-1", VerdictConfirmed)}
		return s
	}()); err != nil {
		t.Fatalf("submit hunt: %v", err)
	}

	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a"}); err == nil || !strings.Contains(err.Error(), "elegible") {
		t.Fatalf("el cazador no debe poder verificar su propio candidato, got %v", err)
	}
	task, err := Next(l, c, NextOptions{AgentID: "verifier-a"})
	if err != nil {
		t.Fatalf("next verify: %v", err)
	}
	if task.Kind != ModeVerify || task.Candidate == nil || task.Candidate.Fingerprint != "fp-1" {
		t.Fatalf("tarea de verificación inesperada: %+v", task)
	}
}

func TestBudgetExhaustionDefersRemainingUnits(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	l.Budget = &Budget{MaxAgentInvocations: 1, Used: 1}
	_, err := Next(l, emptyCandidates(), NextOptions{AgentID: "hunter-a", MaxUnits: 1})
	if err != ErrBudgetExhausted {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if l.RunStatus != StatusIncomplete || l.IncompleteReason != "budget_exhausted" {
		t.Fatalf("estado inesperado: %s/%s", l.RunStatus, l.IncompleteReason)
	}
	for _, u := range l.Units {
		if u.State != StateDeferred || u.Reason != "budget_exhausted" {
			t.Fatalf("unidad no diferida: %+v", u)
		}
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestSubmitAppliesCoveredUnit(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := emptyCandidates()
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next: %v", err)
	}
	out, err := Submit(l, c, huntSubmission("hunter-a", "root/code/sql-injection", DispositionCovered))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.AppliedUnits != 1 || out.Pending != 0 {
		t.Fatalf("resultado inesperado: %+v", out)
	}
	u := l.UnitByID("root/code/sql-injection")
	if u.State != StateCovered || len(u.Checks) != 1 {
		t.Fatalf("unidad no aplicada: %+v", u)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestSubmitRejectsWrongOwnerAndStaysAtomic(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := emptyCandidates()
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next: %v", err)
	}
	before, err := l.JSON()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Submit(l, c, huntSubmission("hunter-b", "root/code/sql-injection", DispositionCovered))
	if err == nil || !strings.Contains(err.Error(), "pertenece") {
		t.Fatalf("se esperaba error de propietario, got %v", err)
	}
	after, _ := l.JSON()
	if string(before) != string(after) {
		t.Fatal("el ledger cambió tras una entrega inválida")
	}
}

func TestSubmitRejectsCandidateWithoutRecord(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := emptyCandidates()
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next: %v", err)
	}
	_, err := Submit(l, c, huntSubmission("hunter-a", "root/code/sql-injection", DispositionCandidate, "fp-1"))
	if err == nil || !strings.Contains(err.Error(), "sin registro") {
		t.Fatalf("se esperaba error por registro faltante, got %v", err)
	}
}

func TestEscalationRequiresSecondIndependentVerifier(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := emptyCandidates()
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next hunt: %v", err)
	}
	hunt := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCandidate, "fp-1")
	hunt.Candidates = []Record{recordFor("fp-1", VerdictNeedsValidation)}
	if _, err := Submit(l, c, hunt); err != nil {
		t.Fatalf("submit hunt: %v", err)
	}

	task, err := Next(l, c, NextOptions{AgentID: "verifier-a"})
	if err != nil || task.Kind != ModeVerify {
		t.Fatalf("next verify: %v %+v", err, task)
	}
	out, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion,
		AgentID:       "verifier-a",
		Verification: &Verification{
			Fingerprint: "fp-1", Decision: VerdictConfirmed, Record: ptrRecord(recordFor("fp-1", VerdictConfirmed)),
		},
	})
	if err != nil {
		t.Fatalf("submit verify: %v", err)
	}
	if out.Escalations != 1 {
		t.Fatalf("se esperaba escalación: %+v", out)
	}
	cand := c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateEscalation || cand.AssignedTo != "" {
		t.Fatalf("candidato mal escalado: %+v", cand)
	}

	task, err = Next(l, c, NextOptions{AgentID: "verifier-a"})
	if err == nil || !strings.Contains(err.Error(), "elegible") {
		t.Fatalf("el mismo verificador no puede repetir, got %v", err)
	}
	task, err = Next(l, c, NextOptions{AgentID: "verifier-b"})
	if err != nil || task.Kind != ModeEscalationCheck {
		t.Fatalf("next escalation: %v %+v", err, task)
	}
	out, err = Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion,
		AgentID:       "verifier-b",
		Verification:  &Verification{Fingerprint: "fp-1", Decision: "verified"},
	})
	if err != nil {
		t.Fatalf("submit escalation check: %v", err)
	}
	if out.Decided != 1 {
		t.Fatalf("se esperaba decisión final: %+v", out)
	}
	cand = c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateDecided || cand.Final == nil || cand.Final.Verdict != VerdictConfirmed {
		t.Fatalf("candidato no decidido: %+v", cand)
	}
}

func TestDowngradeAndRejectionAreFinal(t *testing.T) {
	for _, tc := range []struct {
		proposed string
		decision string
	}{
		{VerdictConfirmed, VerdictNeedsValidation},
		{VerdictConfirmed, VerdictRejected},
	} {
		l := plannerLedger("sql-injection")
		c := emptyCandidates()
		if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
			t.Fatalf("next: %v", err)
		}
		hunt := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCandidate, "fp-1")
		hunt.Candidates = []Record{recordFor("fp-1", tc.proposed)}
		if _, err := Submit(l, c, hunt); err != nil {
			t.Fatalf("submit hunt: %v", err)
		}
		if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
			t.Fatalf("next verify: %v", err)
		}
		out, err := Submit(l, c, &Submission{
			SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
			Verification: &Verification{
				Fingerprint: "fp-1", Decision: tc.decision,
				Record: ptrRecord(recordFor("fp-1", tc.decision)),
			},
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.decision, err)
		}
		if out.Decided != 1 || c.CandidateByFingerprint("fp-1").State != CandidateDecided {
			t.Fatalf("%s: no quedó decidido: %+v", tc.decision, out)
		}
	}
}

func TestSubmitRequiresEveryAssignedUnit(t *testing.T) {
	l := plannerLedger("sql-injection", "command-injection")
	c := emptyCandidates()
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 2})
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(task.Units) != 2 {
		t.Fatalf("se esperaban dos unidades: %+v", task)
	}
	sub := auditSubmissionOne(l, "hunter-a", task.Units[0].Unit.CoverageID)
	_, err = Submit(l, c, sub)
	if err == nil || !strings.Contains(err.Error(), "falta la unidad asignada") {
		t.Fatalf("se esperaba error por unidad omitida, got %v", err)
	}
}

func TestSubmitRejectsDuplicateUnitRows(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := emptyCandidates()
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next: %v", err)
	}
	sub := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCovered)
	sub.Units = append(sub.Units, sub.Units[0])
	_, err := Submit(l, c, sub)
	if err == nil || !strings.Contains(err.Error(), "más de una vez") {
		t.Fatalf("se esperaba error por unidad duplicada, got %v", err)
	}
}

func auditSubmissionOne(l *Ledger, agent, unitID string) *Submission {
	u := l.UnitByID(unitID)
	checks := make([]Check, 0, len(u.StartingPaths))
	for _, p := range u.StartingPaths {
		checks = append(checks, Check{AgentID: agent, ReviewedPaths: []string{p}, Invariant: "i", Method: "source", Result: "r"})
	}
	return &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: agent,
		Units: []UnitResult{{
			CoverageID: unitID, Disposition: DispositionCovered,
			ReviewedPaths: u.StartingPaths, Checks: checks,
			CandidateFingerprints: []string{}, Unresolved: []string{},
		}},
	}
}

func TestSubmitAddsUncoveredSurfaceOnce(t *testing.T) {
	l := plannerLedger("sql-injection")
	c := emptyCandidates()
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next: %v", err)
	}
	sub := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCovered)
	sub.Uncovered = []Uncovered{{
		Surface: "webhook", Domain: "code", Boundary: "trust", Subsystem: "root",
		AttackClass: "webhook-trust", StartingPaths: []string{"main.go"},
		Reason: "superficie no mapeada por el catálogo",
	}}
	out, err := Submit(l, c, sub)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(out.AddedUnits) != 1 {
		t.Fatalf("se esperaba una unidad añadida: %+v", out)
	}
	if u := l.UnitByID(out.AddedUnits[0]); u == nil || u.State != StatePlanned {
		t.Fatalf("unidad añadida mal formada: %+v", u)
	}

	// La misma superficie no se duplica en una entrega posterior.
	sub2 := &Submission{SchemaVersion: SubmissionSchemaVersion, AgentID: "hunter-a", Uncovered: sub.Uncovered}
	out2, err := Submit(l, c, sub2)
	if err != nil {
		t.Fatalf("submit repetido: %v", err)
	}
	if len(out2.AddedUnits) != 0 {
		t.Fatalf("la superficie se duplicó: %+v", out2)
	}
}

func ptrRecord(r Record) *Record { return &r }
