package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	root := writeProject(t, map[string]string{
		"go.mod":  "module example.test/app\n",
		"main.go": "package main\n",
	})
	ledger := buildForTest(t, root, nil)
	store, err := OpenStore(filepath.Join(t.TempDir(), "run-1"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if store.Exists() {
		t.Fatal("el store no debe existir antes de escribir")
	}
	if _, err := store.LoadLedger(); !errors.Is(err, ErrNoAudit) {
		t.Fatalf("err = %v, want ErrNoAudit", err)
	}
	if err := store.SaveLedger(ledger); err != nil {
		t.Fatalf("save ledger: %v", err)
	}
	if !store.Exists() {
		t.Fatal("el ledger debe existir tras escribirlo")
	}
	info, err := os.Stat(store.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos = %o, want 600", info.Mode().Perm())
	}
	loaded, err := store.LoadLedger()
	if err != nil {
		t.Fatalf("load ledger: %v", err)
	}
	before, err := ledger.JSON()
	if err != nil {
		t.Fatal(err)
	}
	after, err := loaded.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("el ledger no sobrevive el round-trip:\n%s\n---\n%s", before, after)
	}
}

func TestStoreCandidatesRoundTrip(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ledger := plannerLedger("sql-injection")
	if _, err := store.LoadCandidates(ledger); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("err = %v, want ErrNoCandidates", err)
	}
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: ledger.Run.ID}
	c.Items = []Candidate{{
		Fingerprint: "fp-1", Unit: "root/code/sql-injection", HunterAgent: "hunter-a",
		Proposed: recordFor("fp-1", VerdictConfirmed), State: CandidatePending,
		Attempts: []VerificationAttempt{},
	}}
	ledger.Units[0].State = StateCandidate
	ledger.Units[0].Owner = "hunter-a"
	ledger.Units[0].Candidates = []string{"fp-1"}
	ledger.Recompute()
	if err := store.SaveCandidates(ledger, c); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := store.LoadCandidates(ledger)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Items) != 1 || loaded.Items[0].Fingerprint != "fp-1" {
		t.Fatalf("candidatos mal cargados: %+v", loaded)
	}
}

func TestStoreFindingsValidation(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	f := validFindings()
	if err := store.SaveFindings(f); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := store.LoadFindings()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].Fingerprint != f.Findings[0].Fingerprint {
		t.Fatalf("hallazgos mal cargados: %+v", loaded)
	}

	bad := validFindings()
	bad.Provenance.EngineVerified = true
	if err := store.SaveFindings(bad); err == nil {
		t.Fatal("se esperaba rechazo de procedencia falsa")
	}
}

func TestWriteArtifactRejectsTraversal(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.WriteArtifact("../fuera.md", []byte("x")); err == nil {
		t.Fatal("se esperaba rechazo de nombre con separadores")
	}
	if err := store.WriteArtifact("REPORT.md", []byte("# informe\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(store.ArtifactPath("REPORT.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "informe") {
		t.Fatalf("contenido inesperado: %q", data)
	}
}

func TestStoreRejectsCorruptLedger(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := os.WriteFile(store.LedgerPath(), []byte(`{"schema_version":"audit-ledger-1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadLedger(); err == nil {
		t.Fatal("se esperaba rechazo de ledger incompleto")
	}
}

func TestTaskJSONIsStable(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	l := plannerLedger("sql-injection", "command-injection")
	task, err := Next(l, emptyCandidates(), NextOptions{AgentID: "hunter-a", Catalog: cat, MaxUnits: 1})
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	first, err := task.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if !strings.Contains(string(first), `"schema_version": "audit-task-1.0.0"`) {
		t.Fatalf("contrato inesperado:\n%s", first)
	}
	// El reloj y el orden no participan: dos tareas iguales serializan igual.
	task2, err := Next(l, emptyCandidates(), NextOptions{AgentID: "hunter-a", Catalog: cat, MaxUnits: 1})
	if err != nil {
		t.Fatalf("next idempotente: %v", err)
	}
	second, err := task2.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("la asignación no es estable:\n%s\n---\n%s", first, second)
	}
}
