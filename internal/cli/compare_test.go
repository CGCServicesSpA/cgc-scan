package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func compareDocs(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	mk := func(name string, findings ...normalize.Finding) string {
		start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
		doc := &report.Document{
			SchemaVersion: "1.0.0",
			Run:           report.NewRun(name, start, time.Second, map[string]any{}),
			Target:        report.Target{Root: "/p", LocalID: report.LocalID("/p"), Units: []report.UnitInfo{}},
			Coverage:      report.Coverage{Scope: report.Scope{Root: "/p"}, Exclusions: []report.ExclusionReport{}, NotAnalyzed: []report.NotAnalyzedReport{}, Units: []report.UnitCoverage{}, Limitations: []string{}},
			Tools:         report.Tools{Engines: []report.EngineReport{}},
			Isolation:     report.Isolation{Level: "configured"},
			Validation:    report.Validation{Recipes: []report.Recipe{}, Unresolved: []report.Unresolved{}},
			Findings:      findings,
			Policy:        report.Policy{FailOn: "high", Exceptions: []report.ExceptionReport{}},
			Errors:        []report.Error{},
		}
		doc.Normalize()
		data, err := report.RenderJSON(doc)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	f := func(fp string) normalize.Finding {
		return normalize.Finding{
			Fingerprint: fp, Kind: normalize.KindCode, Title: "t",
			Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityHigh, Source: "eslint"},
			Locations: []normalize.Location{{Path: "src/a.js"}},
			Sources:   []normalize.SourceRef{{Engine: "eslint"}},
			Policy:    normalize.FindingPolicy{Status: "active"},
		}
	}
	previous := mk("prev", f(strings.Repeat("a", 32)))
	current := mk("cur", f(strings.Repeat("b", 32)))
	return previous, current
}

func TestCompareCommandJSON(t *testing.T) {
	previous, current := compareDocs(t)
	app, stdout, stderr := newTestApp(t)
	code := app.Execute(context.Background(), []string{"compare", previous, current, "--format", "json"})
	if code != 0 {
		t.Fatalf("código = %d: %s", code, stderr.String())
	}
	var res map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}
	if len(res["new"].([]any)) != 1 || len(res["resolved"].([]any)) != 1 {
		t.Fatalf("resultado = %v", res)
	}
}

func TestCompareCommandRejectsInvalidReport(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema_version":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, _ := compareDocs(t)
	app, _, _ := newTestApp(t)
	var stderr bytes.Buffer
	app.Stderr = &stderr
	if code := app.Execute(context.Background(), []string{"compare", bad, previous}); code != 2 {
		t.Fatalf("código = %d, want 2: %s", code, stderr.String())
	}
}
