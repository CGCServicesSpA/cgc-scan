package audit

import (
	"strings"
	"testing"
)

// standardLedger devuelve un ledger con dos pasadas de verificación.
func standardLedger(ids ...string) *Ledger {
	l := plannerLedger(ids...)
	l.Profile = ProfileStandard
	l.Recompute()
	return l
}

func TestMaterialChangeTable(t *testing.T) {
	base := recordFor("fp-1", VerdictConfirmed)
	base.Severity = &Severity{
		Likelihood: Score{Score: "medium", Reason: "requiere autenticación"},
		Impact:     Score{Score: "medium", Reason: "lectura limitada"},
		Overall:    "medium",
	}

	editorial := base
	editorial.Title = "Título reescrito"
	editorial.Description = "Descripción redactada de otra forma."
	editorial.Confidence = &Confidence{Score: "high", Reason: "misma evidencia"}

	if MaterialChange(&base, &editorial) {
		t.Fatal("un cambio de redacción no es material")
	}

	// Promoción y degradación de veredicto: material.
	promoted := base
	promoted.Severity = &Severity{
		Likelihood: base.Severity.Likelihood,
		Impact:     Score{Score: "high", Reason: "ejecución demostrada"},
		Overall:    "high",
	}
	if !MaterialChange(&base, &promoted) {
		t.Fatal("cambiar el impacto es material")
	}
	rejected := recordFor("fp-1", VerdictRejected)
	if !MaterialChange(&base, &rejected) {
		t.Fatal("una degradación de veredicto es material")
	}

	// Causa raíz, traza y ejecución distintas: material.
	rootCause := base
	rootCause.RootCause = "otra causa raíz"
	if !MaterialChange(&base, &rootCause) {
		t.Fatal("cambiar la causa raíz es material")
	}
	trace := base
	trace.Trace = append([]TraceStep{{Kind: "entrypoint", File: "x.go", Line: 1, Scope: "s", Description: "d"}}, base.Trace...)
	if !MaterialChange(&base, &trace) {
		t.Fatal("cambiar la traza es material")
	}
	execution := base
	exec := *base.Execution
	exec.ObservedResult = "otro resultado"
	execution.Execution = &exec
	if !MaterialChange(&base, &execution) {
		t.Fatal("cambiar la ejecución es material")
	}
}

// twoPassFixture construye una corrida standard con un candidato decidido que
// espera revisión final: propuesta, verificación con promoción y revisión de
// escalación.
func twoPassFixture(t *testing.T) (*Ledger, *Candidates) {
	t.Helper()
	l := standardLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next hunt: %v", err)
	}
	hunt := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCandidate, "fp-1")
	hunt.Candidates = []Record{recordFor("fp-1", VerdictNeedsValidation)}
	if _, err := Submit(l, c, hunt); err != nil {
		t.Fatalf("submit hunt: %v", err)
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
	return l, c
}

func TestTwoPassStandardRoutesToFinalReview(t *testing.T) {
	l, c := twoPassFixture(t)
	cand := c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateReviewPending || cand.Final == nil {
		t.Fatalf("el candidato debe esperar revisión final: %+v", cand)
	}
	if cand.AssignedTo != "" {
		t.Fatalf("la revisión debe reasignarse: %+v", cand.AssignedTo)
	}

	// El cazador y los validadores previos no pueden revisar.
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a"}); err == nil || !strings.Contains(err.Error(), "elegible") {
		t.Fatalf("el cazador no puede revisar, got %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err == nil || !strings.Contains(err.Error(), "elegible") {
		t.Fatalf("el validador no puede revisar, got %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-b"}); err == nil || !strings.Contains(err.Error(), "elegible") {
		t.Fatalf("el revisor de escalación no puede repetir, got %v", err)
	}

	// Un revisor independiente recibe el registro final a aprobar.
	task, err := Next(l, c, NextOptions{AgentID: "reviewer-a"})
	if err != nil {
		t.Fatalf("next review: %v", err)
	}
	if task.Kind != ModeFinalReview || task.Candidate == nil || task.Candidate.Final == nil {
		t.Fatalf("tarea de revisión inesperada: %+v", task)
	}
	if task.Candidate.Final.Verdict != VerdictConfirmed {
		t.Fatalf("la revisión debe recibir el registro final: %+v", task.Candidate.Final)
	}

	// El revisor aprueba: el candidato queda decidido con el final intacto.
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "reviewer-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationVerified},
	}); err != nil {
		t.Fatalf("submit review: %v", err)
	}
	if cand.State != CandidateDecided || cand.Final == nil {
		t.Fatalf("el candidato debe quedar decidido: %+v", cand)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("estado inválido tras la revisión: %v", err)
	}
}

func TestFinalReviewMaterialReplaceEscalates(t *testing.T) {
	l, c := twoPassFixture(t)
	if _, err := Next(l, c, NextOptions{AgentID: "reviewer-a"}); err != nil {
		t.Fatal(err)
	}
	// El revisor propone un reemplazo que cambia la causa raíz: material.
	replacement := recordFor("fp-1", VerdictConfirmed)
	replacement.RootCause = "otra causa raíz demostrada"
	out, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "reviewer-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationReplace, Record: ptrRecord(replacement)},
	})
	if err != nil {
		t.Fatalf("submit replace: %v", err)
	}
	if out.Escalations != 1 {
		t.Fatalf("el reemplazo material debe escalar: %+v", out)
	}
	cand := c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateEscalation || cand.Escalated == nil || cand.Escalated.RootCause != replacement.RootCause {
		t.Fatalf("el reemplazo material debe quedar pendiente de revisión: %+v", cand)
	}

	// El autor del reemplazo no puede verificarlo.
	if _, err := Next(l, c, NextOptions{AgentID: "reviewer-a"}); err == nil || !strings.Contains(err.Error(), "elegible") {
		t.Fatalf("el autor del reemplazo no puede verificarlo, got %v", err)
	}

	// Un verificador independiente confirma el reemplazo: vuelve a revisión
	// final, y otro revisor lo aprueba.
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-c"}); err != nil {
		t.Fatalf("next escalation: %v", err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-c",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationVerified},
	}); err != nil {
		t.Fatalf("submit escalation: %v", err)
	}
	if cand.State != CandidateReviewPending {
		t.Fatalf("el reemplazo confirmado debe volver a revisión final: %+v", cand.State)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "reviewer-b"}); err != nil {
		t.Fatalf("next review: %v", err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "reviewer-b",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationVerified},
	}); err != nil {
		t.Fatalf("submit review: %v", err)
	}
	if cand.State != CandidateDecided || cand.Final == nil || cand.Final.RootCause != replacement.RootCause {
		t.Fatalf("estado final inesperado: %+v", cand)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("estado inválido: %v", err)
	}
}

func TestFinalReviewEditorialReplaceApplies(t *testing.T) {
	l, c := twoPassFixture(t)
	if _, err := Next(l, c, NextOptions{AgentID: "reviewer-a"}); err != nil {
		t.Fatal(err)
	}
	// Un reemplazo que solo reescribe la redacción se aplica sin otra firma.
	editorial := recordFor("fp-1", VerdictConfirmed)
	editorial.Title = "Título redactado con más precisión"
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "reviewer-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationReplace, Record: ptrRecord(editorial)},
	}); err != nil {
		t.Fatalf("submit replace: %v", err)
	}
	cand := c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateDecided || cand.Final == nil || cand.Final.Title != editorial.Title {
		t.Fatalf("el reemplazo editorial debe aplicarse: %+v", cand)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("estado inválido: %v", err)
	}
}

func TestQuickKeepsSinglePass(t *testing.T) {
	// quick decide en la misma pasada: sin revisión final.
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatal(err)
	}
	hunt := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCandidate, "fp-1")
	hunt.Candidates = []Record{recordFor("fp-1", VerdictNeedsValidation)}
	if _, err := Submit(l, c, hunt); err != nil {
		t.Fatal(err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: VerdictConfirmed, Record: ptrRecord(recordFor("fp-1", VerdictConfirmed))},
	}); err != nil {
		t.Fatal(err)
	}
	cand := c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateEscalation {
		// La promoción escala también en quick.
		t.Fatalf("la promoción debe escalar en quick: %+v", cand)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-b",
		Verification: &Verification{Fingerprint: "fp-1", Decision: EscalationVerified},
	}); err != nil {
		t.Fatal(err)
	}
	// En quick la escalación confirmada decide directamente.
	if cand.State != CandidateDecided || cand.Final == nil {
		t.Fatalf("quick debe decidir sin segunda pasada: %+v", cand)
	}
}

func TestReopenPreservesPendingReviewPhase(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l, c := twoPassFixture(t)
	if err := store.CommitState(&RunState{Ledger: l, Candidates: c}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("recarga: %v", err)
	}
	cand := loaded.Candidates.CandidateByFingerprint("fp-1")
	if cand == nil || cand.State != CandidateReviewPending {
		t.Fatalf("reabrir debe conservar la fase pendiente: %+v", cand)
	}
}
