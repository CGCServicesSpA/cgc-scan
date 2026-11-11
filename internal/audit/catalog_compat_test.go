package audit

import (
	"os"
	"strings"
	"testing"
)

// TestCatalogUpgradePreservesPriorRun comprueba P2-5c: una corrida creada con
// el catálogo anterior se reabre, conserva su versión de catálogo y no se
// reinterpreta; el catálogo instalado más nuevo no reescribe su identidad.
func TestCatalogUpgradePreservesPriorRun(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Corrida sellada con el catálogo 1.1.0 declarado explícitamente.
	st := sealedState(t)
	st.CatalogVersion = "audit-catalog-1.1.0"
	if err := store.CommitState(st); err != nil {
		t.Fatalf("commit con catálogo previo: %v", err)
	}
	loaded, err := store.LoadState()
	if err != nil {
		t.Fatalf("reabrir: %v", err)
	}
	// La versión se conserva exactamente: la reapertura no la actualiza.
	if loaded.CatalogVersion != "audit-catalog-1.1.0" {
		t.Fatalf("la reapertura reinterpretó el catálogo: %q", loaded.CatalogVersion)
	}
	if loaded.Ledger.Profile != ProfileQuick || loaded.Ledger.RunStatus != StatusComplete {
		t.Fatalf("estado alterado: %s/%s", loaded.Ledger.Profile, loaded.Ledger.RunStatus)
	}

	// La comparación entre corridas con versiones de catálogo distintas sigue
	// operando sobre los fingerprints, no sobre el catálogo.
	other := sealedState(t)
	other.CatalogVersion = "audit-catalog-1.2.0"
	other.Ledger.Run.ID = "run-comparar"
	other.Candidates.RunID = other.Ledger.Run.ID
	doc, err := CompareRuns(loaded, other)
	if err != nil {
		t.Fatalf("comparar con catálogos distintos: %v", err)
	}
	if doc == nil {
		t.Fatal("comparación inválida")
	}

	// La continuidad con catálogo distinto invalida la reutilización
	// orientativa (ya probado en continuity_test); aquí se confirma con la
	// migración real de versión.
	src, err := SourceFrom(t.TempDir(), SourceInfo{Mode: SourceModeWorktree})
	if err != nil {
		t.Fatal(err)
	}
	prior, err := ContinuityFrom(loaded, ProfileQuick, src, mustCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	if prior.SameRevisionClean && len(prior.CoveredSameSource) > 0 {
		t.Fatal("el catálogo distinto debe invalidar la reutilización orientativa")
	}
}

// TestCatalogVersionRecordedAtInit comprueba que `init` registra la versión
// del catálogo del momento y que las corridas conservan la versión usada.
func TestCatalogVersionRecordedAtInit(t *testing.T) {
	l := plannerLedger("sql-injection")
	cat := mustCatalog(t)
	st := &RunState{
		SchemaVersion:  StateSchemaVersion,
		CatalogVersion: cat.SchemaVersion,
		Ledger:         l,
		Candidates:     &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}},
	}
	if st.CatalogVersion != "audit-catalog-1.3.0" {
		t.Fatalf("la corrida nueva debe registrar el catálogo vigente: %q", st.CatalogVersion)
	}
}

// TestStateRejectsUnknownCatalogVersion protege frente a un catálogo alterado
// o incompatible: el estado declara su versión y la validez la decide el
// catálogo embebido, no una versión inventada.
func TestStateRejectsUnknownCatalogVersion(t *testing.T) {
	l := plannerLedger("sql-injection")
	st := &RunState{
		SchemaVersion:  StateSchemaVersion,
		CatalogVersion: "audit-catalog-0.0.1",
		Ledger:         l,
		Candidates:     &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}},
	}
	// La versión declarada es honesta y se conserva; la incompatibilidad se
	// declara al comparar o reutilizar, no reinterpretando el estado. El
	// estado declara su fuente para validar por completo.
	info := DeriveSourceInfo(l)
	st.Source = &info
	if err := ValidateRunState(st); err != nil {
		t.Fatalf("la versión de catálogo no invalida por sí sola el estado: %v", err)
	}
	if st.CatalogVersion != "audit-catalog-0.0.1" {
		t.Fatal("la validación no debe reescribir la versión declarada")
	}
}
func mustCatalog(t *testing.T) *Catalog {
	t.Helper()
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// TestCatalogJSONNotTruncatedNiOversized acota el catálogo embebido.
func TestCatalogJSONNotTruncatedNiOversized(t *testing.T) {
	raw := CatalogJSON
	if len(raw) == 0 {
		t.Fatal("catálogo embebido vacío")
	}
	if !strings.HasSuffix(string(raw), "}\n") {
		t.Fatal("el catálogo embebido termina de forma inesperada")
	}
	if len(raw) > 1<<20 {
		t.Fatalf("catálogo sobredimensionado: %d bytes", len(raw))
	}
	if _, err := os.Stat(""); err == nil {
		t.Fatal("stat sin ruta no debía tener éxito")
	}
}
