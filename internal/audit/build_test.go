package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

func buildForTest(t *testing.T, root string, oos []OutOfScope) *Ledger {
	t.Helper()
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	res, err := discovery.Discover(context.Background(), discovery.Options{Target: root})
	if err != nil {
		t.Fatalf("descubrimiento: %v", err)
	}
	ledger, err := BuildLedger(BuildOptions{
		Catalog: cat, Discovery: res, OutOfScope: oos,
		RunID: "run-1", Now: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC),
		CLIVersion: "test", SourceRef: "rev-1",
	})
	if err != nil {
		t.Fatalf("construir ledger: %v", err)
	}
	return ledger
}

func TestCatalogCoversEveryDiscoveryLanguage(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	for _, lang := range []discovery.Language{
		discovery.Go, discovery.JavaScript, discovery.TypeScript,
		discovery.PHP, discovery.Rust, discovery.Python,
	} {
		if _, ok := cat.Languages[string(lang)]; !ok {
			t.Fatalf("el catálogo no declara el lenguaje %q", lang)
		}
	}
	if cat.ClassByID("dependency-known-vulnerable") == nil {
		t.Fatal("ClassByID no encuentra una clase existente")
	}
	if cat.ClassByID("no-existe") != nil {
		t.Fatal("ClassByID debe devolver nil para una clase inexistente")
	}
}

func TestBuildLedgerFromRealProject(t *testing.T) {
	root := writeProject(t, map[string]string{
		"go.mod":                     "module example.test/app\n\ngo 1.27.3\n",
		"go.sum":                     "",
		"main.go":                    "package main\n\nfunc main() {}\n",
		"internal/db/query.go":       "package db\n",
		"Dockerfile":                 "FROM scratch\n",
		".github/workflows/ci.yml":   "name: ci\n",
		".env":                       "TOKEN=placeholder\n",
		"vendor/ignored/vendored.go": "package ignored\n",
		"node_modules/x/index.js":    "module.exports = {};\n",
	})
	ledger := buildForTest(t, root, nil)

	data, err := ledger.JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if err := ValidateLedger(data); err != nil {
		t.Fatalf("esquema: %v", err)
	}
	decoded, err := DecodeLedger(data)
	if err != nil {
		t.Fatalf("decodificar: %v", err)
	}
	if err := ValidateLedgerSemantics(decoded); err != nil {
		t.Fatalf("semántica: %v", err)
	}

	classes := map[string]bool{}
	for _, u := range ledger.Units {
		classes[u.AttackClass] = true
		for _, p := range u.StartingPaths {
			if !ValidRepoPath(p) {
				t.Fatalf("starting_path no válido: %q", p)
			}
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
				t.Fatalf("starting_path inexistente %q: %v", p, err)
			}
			if strings.Contains(p, "vendor/") || strings.Contains(p, "node_modules/") {
				t.Fatalf("starting_path dentro de un directorio intrínseco: %q", p)
			}
		}
	}
	for _, want := range []string{
		"dependency-known-vulnerable", "dependency-unpinned",
		"secret-in-tree", "secret-default-in-config",
		"sql-injection", "command-injection", "path-traversal",
		"template-injection", "unsafe-deserialization", "unsafe-file-write",
		"weak-crypto", "file-permissions", "network-exposure",
		"ci-untrusted-input", "container-privileged",
	} {
		if !classes[want] {
			t.Fatalf("falta la clase %q en el ledger; presentes: %v", want, classList(classes))
		}
	}
	if classes["php-object-injection"] {
		t.Fatal("un proyecto Go no debe recibir una clase exclusiva de PHP")
	}
}

func TestBuildLedgerIsDeterministic(t *testing.T) {
	root := writeProject(t, map[string]string{
		"go.mod":  "module example.test/app\n",
		"main.go": "package main\n",
	})
	first, err := buildForTest(t, root, nil).JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	second, err := buildForTest(t, root, nil).JSON()
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("el ledger no es determinista:\n%s\n---\n%s", first, second)
	}
}

func TestBuildLedgerMarksOutOfScope(t *testing.T) {
	root := writeProject(t, map[string]string{"main.go": "package main\n"})
	ledger := buildForTest(t, root, []OutOfScope{{
		Unit: "docs", Path: "docs/README.md", Reason: "excluido por --exclude",
	}})
	var found *Unit
	for i := range ledger.Units {
		if ledger.Units[i].AttackClass == "out-of-scope" {
			found = &ledger.Units[i]
		}
	}
	if found == nil {
		t.Fatal("falta la unidad out_of_scope")
	}
	if found.State != StateOutOfScope || found.Reason != "excluido por --exclude" {
		t.Fatalf("unidad fuera de alcance mal formada: %+v", found)
	}
	if ledger.Summary.OutOfScope != 1 {
		t.Fatalf("summary.OutOfScope = %d, want 1", ledger.Summary.OutOfScope)
	}
}

func TestBuildLedgerRespectsStartingPathLimit(t *testing.T) {
	files := map[string]string{"go.mod": "module example.test/app\n"}
	for i := 0; i < 40; i++ {
		files[filepath.ToSlash(filepath.Join("pkg", string(rune('a'+i%26))+string(rune('a'+i/26)), "file.go"))] = "package pkg\n"
	}
	root := writeProject(t, files)
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	ledger := buildForTest(t, root, nil)
	for _, u := range ledger.Units {
		if len(u.StartingPaths) > cat.Limits.MaxStartingPaths {
			t.Fatalf("unidad %s tiene %d starting_paths, tope %d",
				u.CoverageID, len(u.StartingPaths), cat.Limits.MaxStartingPaths)
		}
	}
}

func TestBuildLedgerDisclosesTruncatedReconnaissance(t *testing.T) {
	root := writeProject(t, map[string]string{
		"go.mod": "module example.test/app\n",
		"a.go":   "package main\n",
		"b.go":   "package main\n",
		"c.go":   "package main\n",
		"d.go":   "package main\n",
	})
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	cat.Limits.MaxFilesScanned = 2
	res, err := discovery.Discover(context.Background(), discovery.Options{Target: root})
	if err != nil {
		t.Fatalf("descubrimiento: %v", err)
	}
	ledger, err := BuildLedger(BuildOptions{
		Catalog: cat, Discovery: res, RunID: "run-1",
		Now: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(ledger.Limitations) == 0 {
		t.Fatal("el reconocimiento truncado debe declararse")
	}
	found := false
	for _, lim := range ledger.Limitations {
		if strings.Contains(lim, "truncado") {
			found = true
		}
	}
	if !found {
		t.Fatalf("limitación inesperada: %+v", ledger.Limitations)
	}
	if err := ValidateLedgerSemantics(ledger); err != nil {
		t.Fatalf("semántica: %v", err)
	}
}

func TestBuildLedgerRejectsCoverageIDCollision(t *testing.T) {
	root := writeProject(t, map[string]string{
		"a/b/main.go": "package b\n",
		"a-b/main.go": "package ab\n",
	})
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	res := discovery.Result{Root: root, Units: []discovery.Unit{
		{ID: "a/b", Path: "a/b", Kind: "module", Languages: []discovery.Language{discovery.Go}},
		{ID: "a-b", Path: "a-b", Kind: "module", Languages: []discovery.Language{discovery.Go}},
	}}
	_, err = BuildLedger(BuildOptions{
		Catalog: cat, Discovery: res, RunID: "run-1",
		Now: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "colisiona") {
		t.Fatalf("se esperaba colisión de coverage_id, got %v", err)
	}
}

func TestPriorFromIsContextOnly(t *testing.T) {
	root := writeProject(t, map[string]string{"go.mod": "module example.test/app\n", "main.go": "package main\n"})
	ledger := buildForTest(t, root, nil)
	ledger.Units[0].State = StateCovered
	ledger.Units[0].Owner = "hunter-a"
	ledger.Units[0].ReviewedPaths = []string{"main.go"}
	ledger.Units[0].Checks = []Check{huntCheck("hunter-a")}
	ledger.Recompute()
	ledger.Run.SourceRef = "rev-1"
	ledger.Run.Dirty = false

	findings := &Findings{
		SchemaVersion: FindingsSchemaVersion,
		Provenance:    CallerProvenance(),
		Findings: []Record{
			recordFor("fp-rejected", VerdictRejected),
			recordFor("fp-nv", VerdictNeedsValidation),
		},
	}
	findings.Recompute()

	prior := PriorFrom(ledger, findings, "rev-1", false)
	if prior == nil || !prior.SameRevisionClean {
		t.Fatalf("prior inesperado: %+v", prior)
	}
	if len(prior.CoveredSameSource) != 1 || prior.CoveredSameSource[0] != ledger.Units[0].CoverageID {
		t.Fatalf("unidades cubiertas: %+v", prior.CoveredSameSource)
	}
	if len(prior.RejectedFingerprints) != 1 || len(prior.NeedsValidationFingerprints) != 1 {
		t.Fatalf("fingerprints previos: %+v", prior)
	}
	if PriorFrom(ledger, findings, "rev-2", false).SameRevisionClean {
		t.Fatal("una revisión distinta no puede declararse misma fuente")
	}
	if PriorFrom(ledger, findings, "rev-1", true).SameRevisionClean {
		t.Fatal("un árbol sucio no puede declararse misma fuente")
	}
	ledger.Run.SourceRef = "worktree"
	if PriorFrom(ledger, findings, "worktree", false).SameRevisionClean {
		t.Fatal("sin revisión no hay misma fuente")
	}

	// El contexto no suprime trabajo: las unidades de la corrida nueva siguen
	// planificadas y visibles.
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	res, err := discovery.Discover(context.Background(), discovery.Options{Target: root})
	if err != nil {
		t.Fatalf("descubrimiento: %v", err)
	}
	next, err := BuildLedger(BuildOptions{
		Catalog: cat, Discovery: res, Prior: prior, RunID: "run-2",
		Now: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC), SourceRef: "rev-1",
	})
	if err != nil {
		t.Fatalf("build con prior: %v", err)
	}
	if next.Prior == nil || !next.Prior.SameRevisionClean {
		t.Fatalf("el ledger nuevo debe exponer el contexto previo")
	}
	for _, u := range next.Units {
		if u.State != StatePlanned {
			t.Fatalf("el contexto previo no puede suprimir %s (%s)", u.CoverageID, u.State)
		}
	}
}

func TestBuildLedgerRejectsUnknownProfile(t *testing.T) {
	root := writeProject(t, map[string]string{"main.go": "package main\n"})
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("catálogo: %v", err)
	}
	res, err := discovery.Discover(context.Background(), discovery.Options{Target: root})
	if err != nil {
		t.Fatalf("descubrimiento: %v", err)
	}
	_, err = BuildLedger(BuildOptions{Catalog: cat, Discovery: res, Profile: "express"})
	if err == nil || !strings.Contains(err.Error(), "perfil") {
		t.Fatalf("se esperaba perfil inválido, got %v", err)
	}
}

func classList(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
