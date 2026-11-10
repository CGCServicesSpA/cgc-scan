package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveUnitIdentityAndEvaluateChanges(t *testing.T) {
	root := writeProject(t, map[string]string{
		"go.mod":               "module example.test/app\n\ngo 1.27.3\n",
		"main.go":              "package main\n\nfunc main() {}\n",
		"internal/db/query.go": "package db\n\nfunc Query() {}\n",
	})
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	l := mapUnit("root/code/sql-injection", []string{"main.go", "internal/db/query.go"})

	identity, err := ArchiveUnitIdentity(l, root, cat)
	if err != nil {
		t.Fatalf("archivar identidad: %v", err)
	}
	set, ok := identity["root/code/sql-injection"]
	if !ok || len(set) != 2 {
		t.Fatalf("la identidad debe cubrir dos archivos: %+v", identity)
	}

	// Sin cambios: la unidad no cambió.
	changes, err := EvaluateUnitChanges("root/code/sql-injection", set, l, root, cat)
	if err != nil {
		t.Fatal(err)
	}
	if changes.Changed() {
		t.Fatalf("sin cambios el reparto no debe cambiar: %+v", changes)
	}

	// Un archivo modificado: solo la unidad dependiente cambia.
	if err := writeFileIn(root, "internal/db/query.go", "package db\n\nfunc Query(q string) {}\n"); err != nil {
		t.Fatal(err)
	}
	changes, err = EvaluateUnitChanges("root/code/sql-injection", set, l, root, cat)
	if err != nil {
		t.Fatal(err)
	}
	if !changes.Changed() || len(changes.Modified) != 1 || changes.Modified[0] != "internal/db/query.go" {
		t.Fatalf("modificados: %+v", changes)
	}

	// Un archivo añadido al recorrido de un directorio: la unidad con partida
	// de directorio cubre todo su contenido.
	dirLedger := mapUnit("root/code/db-sweep", []string{"internal/db"})
	dirIdentity, err := ArchiveUnitIdentity(dirLedger, root, cat)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileIn(root, "internal/db/extra.go", "package db\n\nfunc Extra() {}\n"); err != nil {
		t.Fatal(err)
	}
	changes, err = EvaluateUnitChanges("root/code/db-sweep", dirIdentity["root/code/db-sweep"], dirLedger, root, cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Added) != 1 || changes.Added[0] != "internal/db/extra.go" {
		t.Fatalf("añadidos: %+v", changes)
	}

	// Un archivo eliminado.
	if err := os.Remove(filepath.Join(root, "internal/db/query.go")); err != nil {
		t.Fatal(err)
	}
	changes, err = EvaluateUnitChanges("root/code/sql-injection", set, l, root, cat)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(changes.Deleted, "internal/db/query.go") {
		t.Fatalf("eliminados: %+v", changes)
	}
}

func TestContinuityInvalidatesReuseOnCatalogOrProfileChange(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	src, err := SourceFrom(t.TempDir(), SourceInfo{Mode: SourceModeWorktree})
	if err != nil {
		t.Fatal(err)
	}
	priorState := &RunState{
		SchemaVersion:  StateSchemaVersion,
		Source:         &src.Info,
		CatalogVersion: cat.SchemaVersion,
		Ledger:         plannerLedger("sql-injection"),
		Candidates:     &Candidates{SchemaVersion: CandidatesSchemaVersion, Items: []Candidate{}},
	}
	priorState.Ledger.Units[0].State = StateCovered
	priorState.Ledger.Recompute()

	// Cambio de catálogo: la reutilización orientativa caduca.
	staleCat := &RunState{
		SchemaVersion:  StateSchemaVersion,
		Source:         &src.Info,
		CatalogVersion: "audit-catalog-0.9.0",
		Ledger:         plannerLedger("sql-injection"),
		Candidates:     &Candidates{SchemaVersion: CandidatesSchemaVersion, Items: []Candidate{}},
	}
	out, err := ContinuityFrom(staleCat, ProfileQuick, src, cat)
	if err != nil {
		t.Fatal(err)
	}
	if out.SameRevisionClean || len(out.CoveredSameSource) != 0 {
		t.Fatalf("el cambio de catálogo debe invalidar la reutilización: %+v", out)
	}

	// Cambio de perfil: igual.
	out, err = ContinuityFrom(priorState, ProfileDeep, src, cat)
	if err != nil {
		t.Fatal(err)
	}
	if out.SameRevisionClean || len(out.CoveredSameSource) != 0 {
		t.Fatalf("el cambio de perfil debe invalidar la reutilización: %+v", out)
	}

	// Mismo catálogo y perfil: el contexto se conserva.
	out, err = ContinuityFrom(priorState, ProfileQuick, src, cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.CoveredSameSource) != 1 {
		t.Fatalf("el contexto debe conservarse: %+v", out)
	}
}

func TestContinuityReopensRejectedAndExportsStaleConfirmed(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	root := writeProject(t, map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.27.3\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})
	src, err := ResolveSource(root, "worktree", false)
	if err != nil {
		t.Fatal(err)
	}

	// Corrida anterior: una unidad con un candidato confirmado y otro
	// rechazado, con su identidad archivada.
	l := standardLedger("sql-injection")
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{
		candDecided("fp-ok", l.Units[0].CoverageID, "hunter-a", VerdictConfirmed),
		candDecided("fp-no", l.Units[0].CoverageID, "hunter-a", VerdictRejected),
	}}
	l.Recompute()
	findings := &Findings{
		SchemaVersion: FindingsSchemaVersion,
		Provenance:    CallerProvenance(),
		Run:           l.Run,
		Findings:      []Record{*c.CandidateByFingerprint("fp-no").Final},
	}
	findings.Recompute()
	priorState := &RunState{
		SchemaVersion:  StateSchemaVersion,
		Source:         &src.Info,
		CatalogVersion: cat.SchemaVersion,
		Ledger:         l,
		Candidates:     c,
		Findings:       findings,
		UnitIdentity:   map[string]map[string]string{},
	}
	priorState.UnitIdentity[l.Units[0].CoverageID] = map[string]string{
		"main.go": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}

	// El archivo citado cambia: el confirmado exige revalidación y el
	// rechazado se reabre (deja de orientar la prioridad como rechazado).
	if err := writeFileIn(root, "main.go", "package main\n\nfunc main() { changed }\n"); err != nil {
		t.Fatal(err)
	}
	out, err := ContinuityFrom(priorState, ProfileDeep, src, cat)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(out.StaleConfirmed, "fp-ok") {
		t.Fatalf("el confirmado con la fuente cambiada debe exigir revalidación: %v", out.StaleConfirmed)
	}
	if containsString(out.RejectedFingerprints, "fp-no") {
		t.Fatalf("el rechazado con la fuente cambiada se reabre: %v", out.RejectedFingerprints)
	}
	if !containsString(out.StaleRejected, "fp-no") {
		t.Fatalf("el rechazado reabierto debe exportarse: %v", out.StaleRejected)
	}
}

// mapUnit crea un ledger con una unidad para las pruebas de identidad.
func mapUnit(id string, starts []string) *Ledger {
	l := &Ledger{
		SchemaVersion: LedgerSchemaVersion,
		Run:           Run{ID: "run-1", StartedAt: "2026-11-09T00:00:00Z", CLIVersion: "test", SourceRef: "rev-1"},
		Target:        Target{Root: "/tmp/p", LocalID: "p"},
		Profile:       ProfileQuick,
		RunStatus:     StatusInProgress,
		Units:         []Unit{newUnit(id, "root", "code", "input-to-sink", "sql-injection", starts)},
	}
	l.Recompute()
	return l
}

// candDecided crea un candidato decidido con contrato válido.
func candDecided(fp, unit, hunter string, verdict string) Candidate {
	rec := validFindings().Findings[0]
	rec.Fingerprint = fp
	rec.Verdict = verdict
	return Candidate{
		Fingerprint: fp,
		Unit:        unit,
		HunterAgent: hunter,
		Proposed:    rec,
		State:       CandidateDecided,
		Final:       &rec,
		Attempts:    []VerificationAttempt{},
	}
}

// writeFileIn escribe o reemplaza un archivo dentro del proyecto de prueba.
func writeFileIn(root, name, content string) error {
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(content), 0o644)
}
