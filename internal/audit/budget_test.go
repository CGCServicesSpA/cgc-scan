package audit

import (
	"testing"
)

func TestBudgetTableZeroIsUnlimited(t *testing.T) {
	l := plannerLedger("sql-injection")
	l.Budget = nil
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1})
	if err != nil || task.Kind != "hunt" {
		t.Fatalf("sin presupuesto debe repartir: %v", err)
	}
}

func TestBudgetTableInsufficientRefusesHunt(t *testing.T) {
	// quick exige caza + una pasada de verificación: Max=1 no asigna caza.
	l := plannerLedger("sql-injection")
	l.Budget = &Budget{MaxAgentInvocations: 1}
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	_, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1})
	if err != ErrBudgetExhausted {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if l.RunStatus != StatusIncomplete || l.IncompleteReason != "budget_exhausted" {
		t.Fatalf("estado = %s/%s", l.RunStatus, l.IncompleteReason)
	}
	if l.Summary.Planned != 0 || l.Summary.Deferred != 1 {
		t.Fatalf("las unidades planificadas deben diferirse: %+v", l.Summary)
	}

	// standard exige además las dos pasadas y la crítica: Max=2 tampoco.
	ls := standardLedger("sql-injection")
	ls.Budget = &Budget{MaxAgentInvocations: 2}
	cs := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: ls.Run.ID, Items: []Candidate{}}
	if _, err := Next(ls, cs, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != ErrBudgetExhausted {
		t.Fatalf("standard con presupuesto insuficiente debe negarse a cazar: %v", err)
	}
}

func TestBudgetTableExactQuick(t *testing.T) {
	// quick exacto: caza (1) + una pasada de verificación (2).
	l := plannerLedger("sql-injection")
	l.Budget = &Budget{MaxAgentInvocations: 2}
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1})
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	hunt := huntSubmission("hunter-a", task.Units[0].Unit.CoverageID, DispositionCandidate, "fp-1")
	hunt.Candidates = []Record{recordFor("fp-1", VerdictConfirmed)}
	if _, err := Submit(l, c, hunt); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
		t.Fatalf("next verify: %v", err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: VerdictNeedsValidation, Record: ptrRecord(recordFor("fp-1", VerdictNeedsValidation))},
	}); err != nil {
		t.Fatalf("submit verify: %v", err)
	}
	if l.Budget.Used != 2 {
		t.Fatalf("used = %d, want 2", l.Budget.Used)
	}
	if _, err := BuildFindings(l, c); err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.RunStatus != StatusComplete {
		t.Fatalf("presupuesto exacto debe completar la corrida: %s/%s", l.RunStatus, l.IncompleteReason)
	}
}

func TestBudgetTableExactStandardCoversFullChain(t *testing.T) {
	// standard exacto: caza + tres verificaciones (verify, escalación por la
	// promoción, revisión final) + crítica final = 5. La reserva garantiza el
	// mínimo documentado (pasadas + crítica); una promoción consume una
	// invocación extra.
	l := standardLedger("sql-injection")
	l.Budget = &Budget{MaxAgentInvocations: 5}
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1})
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	hunt := huntSubmission("hunter-a", task.Units[0].Unit.CoverageID, DispositionCandidate, "fp-1")
	hunt.Candidates = []Record{recordFor("fp-1", VerdictNeedsValidation)}
	if _, err := Submit(l, c, hunt); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
		t.Fatalf("next verify: %v", err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: VerdictConfirmed, Record: ptrRecord(recordFor("fp-1", VerdictConfirmed))},
	}); err != nil {
		t.Fatalf("submit verify: %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-b"}); err != nil {
		t.Fatalf("next escalation: %v", err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-b",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationVerified},
	}); err != nil {
		t.Fatalf("submit escalation: %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "reviewer-a"}); err != nil {
		t.Fatalf("next review: %v", err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "reviewer-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationVerified},
	}); err != nil {
		t.Fatalf("submit review: %v", err)
	}
	// La ola completó: el crítico cobra la última invocación.
	task, err = Next(l, c, NextOptions{AgentID: "critic-a"})
	if err != nil || task.Kind != "critique" {
		t.Fatalf("next critique: %v %+v", err, task)
	}
	if l.Budget.Used != 5 {
		t.Fatalf("used = %d, want 5", l.Budget.Used)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a", Critique: &Critique{},
	}); err != nil {
		t.Fatalf("submit critique: %v", err)
	}
	if _, err := BuildFindings(l, c); err != nil {
		t.Fatalf("build: %v", err)
	}
	if l.RunStatus != StatusComplete {
		t.Fatalf("la cadena completa debe cerrar con el presupuesto exacto: %s/%s",
			l.RunStatus, l.IncompleteReason)
	}
}

func TestBudgetTableSurplus(t *testing.T) {
	l := standardLedger("sql-injection")
	l.Budget = &Budget{MaxAgentInvocations: 100}
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	coveredAll(t, l, c, "hunter-a")
	if _, err := Next(l, c, NextOptions{AgentID: "critic-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "critic-a", Critique: &Critique{},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildFindings(l, c); err != nil {
		t.Fatal(err)
	}
	if l.RunStatus != StatusComplete || l.Budget.Used > l.Budget.MaxAgentInvocations {
		t.Fatalf("excedente: %s used=%d", l.RunStatus, l.Budget.Used)
	}
}

func TestVerificationExhaustionDefersAndSealsLikeHunt(t *testing.T) {
	// Agotamiento en verificación: igual que en caza, difiere y sella antes
	// de responder; el mensaje de la CLI coincide con el estado persistido.
	l := plannerLedger("sql-injection", "command-injection")
	l.Budget = &Budget{MaxAgentInvocations: 2}
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1})
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	hunt := huntSubmission("hunter-a", task.Units[0].Unit.CoverageID, DispositionCandidate, "fp-1")
	hunt.Candidates = []Record{recordFor("fp-1", VerdictNeedsValidation)}
	if _, err := Submit(l, c, hunt); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
		t.Fatalf("next verify: %v", err)
	}
	// La promoción escala: la revisión de escalación no cabe en el presupuesto.
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: VerdictConfirmed, Record: ptrRecord(recordFor("fp-1", VerdictConfirmed))},
	}); err != nil {
		t.Fatalf("submit verify: %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-b"}); err != ErrBudgetExhausted {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if l.RunStatus != StatusIncomplete || l.IncompleteReason != "budget_exhausted" {
		t.Fatalf("el agotamiento en verificación debe sellar la corrida: %s/%s",
			l.RunStatus, l.IncompleteReason)
	}
	if l.Summary.Deferred != 1 {
		t.Fatalf("la unidad planificada restante debe diferirse: %+v", l.Summary)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido: %v", err)
	}
}

func TestRecoveryDoesNotDoubleCharge(t *testing.T) {
	l := plannerLedger("sql-injection")
	l.Budget = &Budget{MaxAgentInvocations: 10}
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatal(err)
	}
	if l.Budget.Used != 1 {
		t.Fatalf("used = %d, want 1", l.Budget.Used)
	}
	// La recuperación no cobra; la siguiente asignación nueva cobra una vez.
	if err := ResetUnit(l, "root/code/sql-injection", "abandono"); err != nil {
		t.Fatal(err)
	}
	if l.Budget.Used != 1 {
		t.Fatalf("el reinicio no debe cobrar: used=%d", l.Budget.Used)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-b", MaxUnits: 1}); err != nil {
		t.Fatal(err)
	}
	if l.Budget.Used != 2 {
		t.Fatalf("used = %d, want 2 (una asignación nueva)", l.Budget.Used)
	}
}
