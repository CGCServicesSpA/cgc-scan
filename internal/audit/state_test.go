package audit

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// sealedState construye con el broker un estado completo y sellado: dos
// unidades, una con candidato decidido con historial de escalación y otra
// cubierta.
func sealedState(t *testing.T) *RunState {
	t.Helper()
	l := plannerLedger("sql-injection", "command-injection")
	// quick: una pasada de verificación y sin fases de crítica pendientes.
	l.Profile = ProfileQuick
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	task, err := Next(l, c, NextOptions{AgentID: "hunter-a", MaxUnits: 1})
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	unitID := task.Units[0].Unit.CoverageID
	hunt := huntSubmission("hunter-a", unitID, DispositionCandidate, "fp-1")
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
	task2, err := Next(l, c, NextOptions{AgentID: "hunter-b", MaxUnits: 1})
	if err != nil {
		t.Fatalf("next 2: %v", err)
	}
	if _, err := Submit(l, c, huntSubmission("hunter-b", task2.Units[0].Unit.CoverageID, DispositionCovered)); err != nil {
		t.Fatalf("submit 2: %v", err)
	}
	findings, err := BuildFindings(l, c)
	if err != nil {
		t.Fatalf("sealar: %v", err)
	}
	return &RunState{Ledger: l, Candidates: c, Findings: findings}
}

func TestCommitStateRoundTrip(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := sealedState(t)
	if err := store.CommitState(st); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !store.Exists() {
		t.Fatal("el estado debe existir tras el commit")
	}
	info, err := os.Stat(store.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos = %o, want 600", info.Mode().Perm())
	}
	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Ledger.Run.ID != st.Ledger.Run.ID || loaded.Ledger.RunStatus != StatusComplete {
		t.Fatalf("ledger mal cargado: %+v", loaded.Ledger)
	}
	if len(loaded.Candidates.Items) != 1 || loaded.Candidates.Items[0].State != CandidateDecided {
		t.Fatalf("candidatos mal cargados: %+v", loaded.Candidates.Items)
	}
	if loaded.Findings == nil || loaded.Findings.Summary.Confirmed != 1 {
		t.Fatalf("hallazgos mal cargados: %+v", loaded.Findings)
	}
	// Las vistas derivadas quedaron regeneradas desde el estado.
	for _, name := range []string{LedgerFilename, CandidatesFilename, FindingsFilename} {
		if _, statErr := os.Stat(store.ArtifactPath(name)); statErr != nil {
			t.Fatalf("falta la vista %s: %v", name, statErr)
		}
	}
}

func TestLoadStateReadsLegacyTwoFileRun(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := sealedState(t)
	// Formato heredado: solo los dos archivos independientes, sin hallazgos.
	if err := store.writeLedgerView(st.Ledger); err != nil {
		t.Fatal(err)
	}
	if err := store.writeCandidatesView(st.Candidates); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("carga legada: %v", err)
	}
	if loaded.Ledger.Run.ID != st.Ledger.Run.ID || len(loaded.Candidates.Items) != 1 {
		t.Fatalf("estado legado mal cargado: %+v", loaded.Ledger)
	}
	if loaded.Findings != nil {
		t.Fatal("el legado no debió inventar hallazgos")
	}
	// La primera escritura migra a state.json.
	if err := store.CommitState(loaded); err != nil {
		t.Fatalf("commit migrado: %v", err)
	}
	if _, err := os.Stat(store.StatePath()); err != nil {
		t.Fatalf("falta state.json tras migrar: %v", err)
	}
	again, err := store.LoadState()
	if err != nil {
		t.Fatalf("recarga: %v", err)
	}
	if again.SchemaVersion != StateSchemaVersion {
		t.Fatalf("esquema = %q", again.SchemaVersion)
	}
}

func TestLoadStateRejectsLegacyInconsistent(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	l := plannerLedger("sql-injection")
	l.Units[0].State = StateCandidate
	l.Units[0].Owner = "hunter-a"
	l.Units[0].ReviewedPaths = []string{"main.go"}
	l.Units[0].Checks = []Check{huntCheck("hunter-a")}
	l.Units[0].Candidates = []string{"fp-1"}
	l.Recompute()
	if err := store.writeLedgerView(l); err != nil {
		t.Fatal(err)
	}
	// Unidad candidate sin candidato correspondiente: corrida dañada.
	_, err = store.LoadState()
	if err == nil || !strings.Contains(err.Error(), "estado de verificación") {
		t.Fatalf("err = %v, want corrida dañada explícita", err)
	}
}

func TestCommitStateFailsWithoutSideEffects(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := sealedState(t)
	if err := store.CommitState(st); err != nil {
		t.Fatalf("commit inicial: %v", err)
	}
	before, err := os.ReadFile(store.StatePath())
	if err != nil {
		t.Fatal(err)
	}

	// Un estado inválido se rechaza antes de escribir cualquier archivo: la
	// validación es previa a la persistencia, así que el commit fallido no
	// deja estado parcial ni toca el estado vigente.
	bad := sealedState(t)
	bad.Candidates.Items[0].Unit = "root/nope/x"
	if err := store.CommitState(bad); err == nil || !strings.Contains(err.Error(), "root/nope/x") {
		t.Fatalf("err = %v, want rechazo por referencia inexistente", err)
	}
	after, err := os.ReadFile(store.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("un commit fallido modificó el estado")
	}

	// Y el estado sigue cargando íntegro.
	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("recarga: %v", err)
	}
	if loaded.Ledger.RunStatus != StatusComplete {
		t.Fatalf("estado corrompido: %s", loaded.Ledger.RunStatus)
	}
}

func TestCommitStateViewFailureKeepsStateCommitted(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := sealedState(t)
	if err := store.CommitState(st); err != nil {
		t.Fatalf("commit inicial: %v", err)
	}

	// Fallo en la segunda escritura: la vista de hallazgos no puede
	// regenerarse. El estado ya quedó confirmado y sigue cargando.
	if err := os.Remove(store.FindingsPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store.FindingsPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	// Una mutación en la corrida reabierta: mover una unidad a planned sería
	// inválido; en su lugar, degradar el estado sellado no es posible, así
	// que se recommittea el mismo estado para provocar la regeneración.
	if err := store.CommitState(st); err == nil || !strings.Contains(err.Error(), "vista derivada") {
		t.Fatalf("err = %v, want fallo de vista con estado confirmado", err)
	}
	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("el estado debe seguir cargando: %v", err)
	}
	if loaded.Ledger.RunStatus != StatusComplete || len(loaded.Candidates.Items) != 1 {
		t.Fatalf("estado inconsistente: %+v", loaded.Ledger)
	}

	// Reparado el obstáculo, repetir el commit regenera las vistas y es
	// idempotente: no vuelve a aplicar operación alguna.
	if err := os.Remove(store.FindingsPath()); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitState(st); err != nil {
		t.Fatalf("recommit: %v", err)
	}
	data, err := os.ReadFile(store.FindingsPath())
	if err != nil {
		t.Fatal(err)
	}
	var view Findings
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	if view.Run.ID != st.Ledger.Run.ID || view.Summary.Confirmed != 1 {
		t.Fatalf("vista regenerada inconsistente: %+v", view)
	}
}

func TestLoadStateRejectsCorruptStateFile(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := os.WriteFile(store.StatePath(), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadState(); err == nil {
		t.Fatal("se esperaba rechazo de JSON inválido")
	}

	// Un estado con esquema incorrecto también se rechaza, sin caer al legado.
	if err := os.WriteFile(store.StatePath(), []byte("{\"schema_version\":\"otra\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = store.LoadState()
	if err == nil || !strings.Contains(err.Error(), "esquema") {
		t.Fatalf("err = %v, want rechazo de esquema", err)
	}
}

func TestValidateRunStateRequiresAllDocuments(t *testing.T) {
	l := plannerLedger("sql-injection")
	if err := ValidateRunState(&RunState{Ledger: l}); err == nil ||
		!strings.Contains(err.Error(), "estado de verificación") {
		t.Fatalf("err = %v, want falta estado de verificación", err)
	}
	if err := ValidateRunState(nil); !errors.Is(err, err) || err == nil {
		t.Fatal("se esperaba rechazo de estado nulo")
	}
}
