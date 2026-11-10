package audit

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// verificationLifecycle construye con el broker real el ciclo completo de un
// candidato: propuesta de caza, verificación y, si escala, la revisión de
// escalación. Valida el estado en cada etapa y devuelve el resultado final,
// de modo que las pruebas validen lo que el broker de verdad produce.
func verificationLifecycle(t *testing.T, proposed, first string, second *Verification) (*Ledger, *Candidates) {
	t.Helper()
	l := plannerLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if _, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1}); err != nil {
		t.Fatalf("next hunt: %v", err)
	}
	hunt := huntSubmission("hunter-a", "root/code/sql-injection", DispositionCandidate, "fp-1")
	hunt.Candidates = []Record{recordFor("fp-1", proposed)}
	if _, err := Submit(l, c, hunt); err != nil {
		t.Fatalf("submit hunt: %v", err)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("pending válido rechazado: %v", err)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-a"}); err != nil {
		t.Fatalf("next verify: %v", err)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("pending asignado rechazado: %v", err)
	}
	out, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-a",
		Verification: &Verification{Fingerprint: "fp-1", Decision: first, Record: ptrRecord(recordFor("fp-1", first))},
	})
	if err != nil {
		t.Fatalf("submit verify: %v", err)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("estado tras verificar rechazado: %v", err)
	}
	if out.Escalations == 0 {
		return l, c
	}
	if cand := c.CandidateByFingerprint("fp-1"); cand.State != CandidateEscalation {
		t.Fatalf("se esperaba escalación: %+v", cand)
	}
	if _, err := Next(l, c, NextOptions{AgentID: "verifier-b"}); err != nil {
		t.Fatalf("next escalation: %v", err)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("escalación asignada rechazada: %v", err)
	}
	if _, err := Submit(l, c, &Submission{
		SchemaVersion: SubmissionSchemaVersion, AgentID: "verifier-b",
		Verification: second,
	}); err != nil {
		t.Fatalf("submit escalation check: %v", err)
	}
	return l, c
}

func TestValidateCandidatesAcceptsBrokerStates(t *testing.T) {
	// Decidido por degradación, sin historial de escalación.
	l, c := verificationLifecycle(t, VerdictConfirmed, VerdictNeedsValidation, nil)
	cand := c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateDecided || cand.Final == nil || cand.Escalated != nil {
		t.Fatalf("estado inesperado: %+v", cand)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("decided sin escalación rechazado: %v", err)
	}

	// Decidido con historial de escalación: verified sostiene el escalado.
	l, c = verificationLifecycle(t, VerdictNeedsValidation, VerdictConfirmed,
		&Verification{Fingerprint: "fp-1", Decision: EscalationVerified})
	cand = c.CandidateByFingerprint("fp-1")
	if cand.State != CandidateDecided || cand.Escalated == nil {
		t.Fatalf("se esperaba decided con historial: %+v", cand)
	}
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("decided con escalación rechazado: %v", err)
	}
	if err := ValidateLedgerSemantics(l); err != nil {
		t.Fatalf("ledger inválido tras el ciclo: %v", err)
	}

	// Decidido con historial de escalación: replace sustituye al escalado.
	l, c = verificationLifecycle(t, VerdictNeedsValidation, VerdictConfirmed,
		&Verification{Fingerprint: "fp-1", Decision: EscalationReplace, Record: ptrRecord(recordFor("fp-1", VerdictNeedsValidation))})
	if err := ValidateCandidates(c, l); err != nil {
		t.Fatalf("decided por replace rechazado: %v", err)
	}

	// El estado inicial de una corrida sin candidatos también es válido.
	empty := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if err := ValidateCandidates(empty, plannerLedger("sql-injection")); err != nil {
		t.Fatalf("candidatos vacíos rechazados: %v", err)
	}
}

func TestValidateCandidatesRejectsCorruptStates(t *testing.T) {
	// Cada mutación parte del estado válido reconstruido con el broker.
	mutations := map[string]func(*Ledger, *Candidates){
		"verificador igual al cazador": func(_ *Ledger, c *Candidates) {
			c.Items[0].Attempts[1].AgentID = "hunter-a"
		},
		"asignado igual al cazador": func(_ *Ledger, c *Candidates) {
			c.Items[0].State = CandidatePending
			c.Items[0].Final = nil
			c.Items[0].Attempts = []VerificationAttempt{}
			c.Items[0].AssignedTo = "hunter-a"
		},
		"unidad inexistente": func(_ *Ledger, c *Candidates) {
			c.Items[0].Unit = "root/nope/sql-injection"
		},
		"unidad no declara el fingerprint": func(l *Ledger, _ *Candidates) {
			l.Units[0].Candidates = nil
			l.Recompute()
		},
		"fingerprint divergente en proposed": func(_ *Ledger, c *Candidates) {
			c.Items[0].Proposed.Fingerprint = "fp-otro"
		},
		"fingerprint divergente en final": func(_ *Ledger, c *Candidates) {
			c.Items[0].Final.Fingerprint = "fp-otro"
		},
		"fingerprint divergente en escalado": func(_ *Ledger, c *Candidates) {
			c.Items[0].Escalated.Fingerprint = "fp-otro"
		},
		"decided sin final": func(_ *Ledger, c *Candidates) {
			c.Items[0].Final = nil
		},
		"escalación sin escalated": func(_ *Ledger, c *Candidates) {
			c.Items[0].State = CandidateEscalation
			c.Items[0].Final = nil
			c.Items[0].Escalated = nil
		},
		"pending con final": func(_ *Ledger, c *Candidates) {
			c.Items[0].State = CandidatePending
			c.Items[0].Attempts = []VerificationAttempt{}
			c.Items[0].AssignedTo = ""
		},
		"decided con verificador asignado": func(_ *Ledger, c *Candidates) {
			c.Items[0].AssignedTo = "verifier-c"
		},
		"estado desconocido": func(_ *Ledger, c *Candidates) {
			c.Items[0].State = "misterio"
		},
		"escalado que no supera al propuesto": func(_ *Ledger, c *Candidates) {
			c.Items[0].Proposed = recordFor("fp-1", VerdictConfirmed)
		},
		"intervención repetida": func(_ *Ledger, c *Candidates) {
			c.Items[0].Attempts[1].AgentID = c.Items[0].Attempts[0].AgentID
		},
		"cazador propone rejected": func(_ *Ledger, c *Candidates) {
			c.Items[0].Proposed = recordFor("fp-1", VerdictRejected)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			l, c := verificationLifecycle(t, VerdictNeedsValidation, VerdictConfirmed,
				&Verification{Fingerprint: "fp-1", Decision: EscalationVerified})
			mutate(l, c)
			err := ValidateCandidates(c, l)
			if err == nil {
				t.Fatalf("se esperaba rechazo de %q", name)
			}
			if !strings.Contains(err.Error(), "fp-1") {
				t.Fatalf("el error debe identificar al candidato: %v", err)
			}
		})
	}
}

func TestValidateCandidatesRejectsIncoherentDocument(t *testing.T) {
	l, c := verificationLifecycle(t, VerdictNeedsValidation, VerdictConfirmed,
		&Verification{Fingerprint: "fp-1", Decision: EscalationVerified})
	other := plannerLedger("sql-injection")
	other.Run.ID = "run-otra"
	other.Units[0].State = StateCandidate
	other.Units[0].Owner = "hunter-a"
	other.Units[0].ReviewedPaths = []string{"main.go"}
	other.Units[0].Checks = []Check{huntCheck("hunter-a")}
	other.Units[0].Candidates = []string{"fp-1"}
	other.Recompute()
	if err := ValidateCandidates(c, other); err == nil || !strings.Contains(err.Error(), "run_id") {
		t.Fatalf("se esperaba rechazo por run_id incoherente, got %v", err)
	}
	dup := c.Items[0]
	c.Items = append(c.Items, dup)
	err := ValidateCandidates(c, l)
	if err == nil || !strings.Contains(err.Error(), "duplicado") {
		t.Fatalf("se esperaba rechazo por fingerprint duplicado, got %v", err)
	}
}

func TestDecodeCandidatesRequiresEOFAfterObject(t *testing.T) {
	valid, err := json.MarshalIndent(&Candidates{
		SchemaVersion: CandidatesSchemaVersion, RunID: "run-1", Items: []Candidate{},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	valid = append(valid, '\n')

	if _, err := DecodeCandidates(append(append([]byte{}, valid...), []byte("\n  \t")...)); err != nil {
		t.Fatalf("el espacio residual debe aceptarse: %v", err)
	}
	for _, bad := range []struct {
		name string
		tail string
	}{
		{"segundo objeto", "\n{\"schema_version\":\"audit-candidates-1.0.0\"}"},
		{"basura", "\nbazura"},
		{"null", "\nnull"},
		{"array", "[]"},
	} {
		data := append(append([]byte{}, valid...), []byte(bad.tail)...)
		if _, err := DecodeCandidates(data); err == nil {
			t.Fatalf("%s: se esperaba rechazo de contenido posterior al objeto", bad.name)
		}
	}
	if _, err := DecodeCandidates(append(append([]byte{}, valid...), '{')); err == nil {
		t.Fatal("se esperaba rechazo de objeto truncado")
	}
}

// candidateJSON serializa el estado producido por el broker tras aplicar una
// mutación, para probar la carga desde disco de estados corruptos.
func candidateJSON(t *testing.T, mutate func(*Candidates)) []byte {
	t.Helper()
	_, c := verificationLifecycle(t, VerdictNeedsValidation, VerdictConfirmed,
		&Verification{Fingerprint: "fp-1", Decision: EscalationVerified})
	mutate(c)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func TestLoadCandidatesRejectsCorruptFileWithoutSideEffects(t *testing.T) {
	l := plannerLedger("sql-injection")
	cases := []struct {
		name    string
		content []byte
		wantErr string
	}{
		{
			name: "verificador igual al cazador",
			content: candidateJSON(t, func(c *Candidates) {
				c.Items[0].Attempts[1].AgentID = "hunter-a"
			}),
			wantErr: "no puede verificar su propio candidato",
		},
		{
			name: "rama final incorrecta",
			content: candidateJSON(t, func(c *Candidates) {
				c.Items[0].Final = nil
			}),
			wantErr: "decided exige final",
		},
		{
			name: "estado incompatible",
			content: candidateJSON(t, func(c *Candidates) {
				c.Items[0].State = "misterio"
			}),
			wantErr: "estado desconocido",
		},
		{
			name: "run_id incoherente",
			content: candidateJSON(t, func(c *Candidates) {
				c.RunID = "run-otra"
			}),
			wantErr: "run_id",
		},
		{
			name:    "campo desconocido",
			content: []byte("{\"schema_version\":\"audit-candidates-1.0.0\",\"run_id\":\"run-1\",\"items\":[],\"extra\":1}\n"),
			wantErr: "unknown field",
		},
	}
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(store.CandidatesPath(), tc.content, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := store.LoadCandidates(l)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			after, err := os.ReadFile(store.CandidatesPath())
			if err != nil {
				t.Fatal(err)
			}
			if string(tc.content) != string(after) {
				t.Fatal("una carga fallida modificó el archivo")
			}
		})
	}
}

func TestSaveCandidatesRejectsWithoutWriting(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ledger := plannerLedger("sql-injection")
	good := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: ledger.Run.ID, Items: []Candidate{}}
	if err := store.SaveCandidates(ledger, good); err != nil {
		t.Fatalf("save válido: %v", err)
	}
	before, err := os.ReadFile(store.CandidatesPath())
	if err != nil {
		t.Fatal(err)
	}

	bad := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: "run-otra", Items: []Candidate{}}
	if err := store.SaveCandidates(ledger, bad); err == nil {
		t.Fatal("se esperaba rechazo por run_id incoherente")
	}
	if err := store.SaveCandidates(nil, good); err == nil {
		t.Fatal("se esperaba rechazo sin ledger")
	}
	after, err := os.ReadFile(store.CandidatesPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("una persistencia rechazada modificó el archivo")
	}
}

func TestLoadCandidatesMissingFileIsExplicit(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_, err = store.LoadCandidates(plannerLedger("sql-injection"))
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("err = %v, want ErrNoCandidates", err)
	}
}
