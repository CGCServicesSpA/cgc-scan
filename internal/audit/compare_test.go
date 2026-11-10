package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// compareFixtures crea dos corridas comparables: una anterior con fp-1
// confirmado y una actual configurable.
func compareFixtures() (*RunState, *RunState) {
	priorState := &RunState{
		SchemaVersion:  StateSchemaVersion,
		CatalogVersion: "audit-catalog-1.1.0",
		Ledger:         plannerLedger("sql-injection"),
		Candidates: &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: "run-prior", Items: []Candidate{
			candDecided("fp-1", "root/code/sql-injection", "hunter-a", VerdictConfirmed),
		}},
	}
	priorState.Ledger.Run.ID = "run-prior"
	currentState := &RunState{
		SchemaVersion:  StateSchemaVersion,
		CatalogVersion: "audit-catalog-1.1.0",
		Ledger:         plannerLedger("sql-injection"),
		Candidates:     &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: "run-actual", Items: []Candidate{}},
	}
	currentState.Ledger.Run.ID = "run-actual"
	return priorState, currentState
}

func TestCompareClassifiesPersistentAndNew(t *testing.T) {
	prior, current := compareFixtures()
	// La corrida actual confirma fp-1 y añade fp-2.
	current.Candidates.Items = append(current.Candidates.Items,
		candDecided("fp-1", "root/code/sql-injection", "hunter-b", VerdictConfirmed),
		candDecided("fp-2", "root/code/sql-injection", "hunter-c", VerdictConfirmed),
	)
	doc, err := CompareRuns(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Persistent != 1 || doc.Summary.New != 1 {
		t.Fatalf("resumen inesperado: %+v", doc.Summary)
	}
	entry := doc.Entries[0]
	if entry.Fingerprint != "fp-1" || entry.Classification != ComparePersistent {
		t.Fatalf("fp-1 debe ser persistent: %+v", entry)
	}
	if doc.Entries[1].Fingerprint != "fp-2" || doc.Entries[1].Classification != CompareNew {
		t.Fatalf("fp-2 debe ser new: %+v", doc.Entries[1])
	}
}

func TestCompareResolvedRequiresCurrentEvidence(t *testing.T) {
	prior, current := compareFixtures()
	// Corrida actual incompleta sin el registro: sin evaluación.
	doc, err := CompareRuns(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Summary.NotEvaluated != 1 || doc.Entries[0].Classification != CompareNotEvaluated {
		t.Fatalf("una corrida incompleta no puede declarar resolved: %+v", doc.Entries[0])
	}

	// Corrida actual completa sin el registro: resuelto con evidencia.
	current.Ledger.RunStatus = StatusComplete
	doc, err = CompareRuns(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Resolved != 1 || doc.Entries[0].Classification != CompareResolved {
		t.Fatalf("una corrida completa puede declarar resolved: %+v", doc.Entries[0])
	}

	// Corrida bloqueada: sin falsos resolved.
	current.Ledger.RunStatus = StatusIncomplete
	current.Ledger.IncompleteReason = "budget_exhausted"
	doc, err = CompareRuns(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Resolved != 0 {
		t.Fatalf("una corrida bloqueada no puede declarar resolved: %+v", doc.Summary)
	}
}

func TestCompareRefutedIsResolved(t *testing.T) {
	prior, current := compareFixtures()
	// La corrida actual refuta el registro: resuelto con evidencia de
	// evaluación.
	current.Candidates.Items = append(current.Candidates.Items,
		candDecided("fp-1", "root/code/sql-injection", "hunter-b", VerdictRejected),
	)
	doc, err := CompareRuns(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Resolved != 1 || doc.Entries[0].Classification != CompareResolved {
		t.Fatalf("un registro refutado es resolved: %+v", doc.Entries[0])
	}
	if doc.Entries[0].Current == nil || doc.Entries[0].Current.Verdict != VerdictRejected {
		t.Fatalf("el veredicto actual debe archivarse: %+v", doc.Entries[0])
	}
}

func TestCompareStaleSourceIsNotResolved(t *testing.T) {
	prior, current := compareFixtures()
	// La corrida actual es completa pero marca el registro con cambio de
	// fuente: no puede declararse resuelto.
	current.Ledger.RunStatus = StatusComplete
	current.Ledger.Prior = &PriorRun{RunID: "run-prior", StaleConfirmed: []string{"fp-1"}}
	doc, err := CompareRuns(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Resolved != 0 || doc.Entries[0].Classification != CompareNotEvaluated {
		t.Fatalf("un registro con la fuente cambiada no es resolved: %+v", doc.Entries[0])
	}
	if !strings.Contains(doc.Entries[0].Reason, "revalidación") {
		t.Fatalf("la razón debe exigir revalidación: %q", doc.Entries[0].Reason)
	}
}

func TestCompareFollowsConsolidationRelations(t *testing.T) {
	prior, current := compareFixtures()
	// La corrida actual consolidó fp-1 en fp-2: el defecto persiste por la
	// relación de consolidación.
	merged := candDecided("fp-1", "root/code/sql-injection", "hunter-b", VerdictConfirmed)
	merged.MergedInto = "fp-2"
	current.Candidates.Items = append(current.Candidates.Items, merged,
		candDecided("fp-2", "root/code/sql-injection", "hunter-c", VerdictConfirmed),
	)
	doc, err := CompareRuns(prior, current)
	if err != nil {
		t.Fatal(err)
	}
	entry := doc.Entries[0]
	if entry.Fingerprint != "fp-1" || entry.Classification != ComparePersistent {
		t.Fatalf("la relación de consolidación debe sostener persistent: %+v", entry)
	}
}

func TestCompareRejectsIncompatibleVersionsAndSameRun(t *testing.T) {
	prior, current := compareFixtures()
	current.Ledger.SchemaVersion = "audit-ledger-9.9.9"
	if _, err := CompareRuns(prior, current); err == nil {
		t.Fatal("se esperaba rechazo de versiones incompatibles")
	}
	current.Ledger.SchemaVersion = prior.Ledger.SchemaVersion
	current.Ledger.Run.ID = prior.Ledger.Run.ID
	if _, err := CompareRuns(prior, current); err == nil {
		t.Fatal("se esperaba rechazo de comparar una corrida consigo misma")
	}
}

func TestCompareDoesNotModifyRuns(t *testing.T) {
	prior, current := compareFixtures()
	current.Candidates.Items = append(current.Candidates.Items,
		candDecided("fp-1", "root/code/sql-injection", "hunter-b", VerdictConfirmed))
	before, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompareRuns(prior, current); err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("la comparación modificó la corrida")
	}
}
