package projectstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func paths(t *testing.T) platform.Paths {
	t.Helper()
	dir := t.TempDir()
	return platform.Paths{
		ConfigDir: filepath.Join(dir, "config"),
		DataDir:   filepath.Join(dir, "data"),
		CacheDir:  filepath.Join(dir, "cache"),
	}
}

func reportFor(root string) *report.Document {
	doc := &report.Document{
		Run: report.Run{ID: "20261027T000000Z-aaaa", CLIVersion: "0.1.0"},
		Target: report.Target{Root: root, LocalID: report.LocalID(root), Units: []report.UnitInfo{
			{ID: "project", Path: ".", Kind: "repository"}, {ID: "svc", Path: "svc", Kind: "module"},
		}},
		Coverage: report.Coverage{
			Scope: report.Scope{Root: root}, Exclusions: []report.ExclusionReport{},
			NotAnalyzed: []report.NotAnalyzedReport{}, Units: []report.UnitCoverage{},
			Limitations: []string{},
		},
		Tools:      report.Tools{Engines: []report.EngineReport{}},
		Isolation:  report.Isolation{Level: "configured"},
		Validation: report.Validation{Recipes: []report.Recipe{}, Unresolved: []report.Unresolved{}},
		Policy:     report.Policy{FailOn: "high", Exceptions: []report.ExceptionReport{}},
		Findings: []normalize.Finding{{
			Fingerprint: strings.Repeat("a", 32), Kind: normalize.KindVulnerability,
			Title: "x/text", Severity: normalize.SeverityInfo{Normalized: normalize.SeverityHigh, Source: "trivy"},
			Sources:   []normalize.SourceRef{{Engine: "trivy"}},
			Locations: []normalize.Location{{Path: "svc/go.mod"}},
			Package:   &normalize.PackageRef{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.0"},
		}},
		Errors: []report.Error{},
	}
	doc.Normalize()
	return doc
}

func TestStoreRoundTripAndLayout(t *testing.T) {
	p := paths(t)
	root := t.TempDir()
	s, err := Open(p, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Dir(), filepath.Join(p.CacheDir, "projects")) {
		t.Fatalf("directorio = %s", s.Dir())
	}
	doc := reportFor(root)
	if err := s.SaveLatest(doc); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBaseline(doc); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadLatest()
	if err != nil {
		t.Fatal(err)
	}
	if got.Run.ID != doc.Run.ID || len(got.Findings) != 1 {
		t.Fatalf("latest = %+v", got.Run)
	}
	if !s.HasBaseline() {
		t.Fatal("falta la línea base")
	}
	if _, err := s.LoadBaseline(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"latest.json", "baseline.json"} {
		info, err := os.Stat(filepath.Join(s.Dir(), name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s: permisos = %o", name, info.Mode().Perm())
		}
	}
	info, err := os.Stat(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("directorio: permisos = %o", info.Mode().Perm())
	}
}

func TestStoreIndexAndUnitResults(t *testing.T) {
	p := paths(t)
	root := t.TempDir()
	s, err := Open(p, root)
	if err != nil {
		t.Fatal(err)
	}
	doc := reportFor(root)
	idx := BuildIndex(doc)
	if idx.Findings[strings.Repeat("a", 32)].Unit != "svc" {
		t.Fatalf("unidad inferida = %+v", idx.Findings[strings.Repeat("a", 32)])
	}
	if err := s.SaveIndex(idx); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.LoadIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Findings) != 1 {
		t.Fatalf("índice = %+v", loaded)
	}
	res := UnitResult{
		Engine: "trivy", Unit: "svc", Status: "completed", Key: "k",
		Findings: doc.Findings, At: time.Now().UTC(),
	}
	if err := s.SaveUnit(res); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadUnit("trivy", "svc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Key != "k" || len(got.Findings) != 1 {
		t.Fatalf("resultado = %+v", got)
	}
}

func TestLoadLatestMissingIsExplicit(t *testing.T) {
	p := paths(t)
	s, err := Open(p, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadLatest(); err == nil {
		t.Fatal("se esperaba error sin reporte")
	}
	if s.HasBaseline() {
		t.Fatal("no debería existir línea base")
	}
}

func TestBuildIndexMapsAllEnginesAndGroup(t *testing.T) {
	root := t.TempDir()
	doc := reportFor(root)
	doc.Target.Units = []report.UnitInfo{
		{ID: "project", Path: "."},
		{ID: "svc", Path: "svc"},
	}
	doc.Findings[0].Sources = append(doc.Findings[0].Sources, normalize.SourceRef{Engine: "govulncheck"})
	doc.RemediationGroups = []report.RemediationGroup{{ID: "rg-go-golang.org/x/text", Fixes: []string{strings.Repeat("a", 32)}}}
	idx := BuildIndex(doc)
	e := idx.Findings[strings.Repeat("a", 32)]
	if e.Unit != "svc" {
		t.Fatalf("unidad = %q", e.Unit)
	}
	if strings.Join(e.Engines, ",") != "govulncheck,trivy" {
		t.Fatalf("motores = %v", e.Engines)
	}
	if e.Group != "rg-go-golang.org/x/text" {
		t.Fatalf("grupo = %q", e.Group)
	}
}
