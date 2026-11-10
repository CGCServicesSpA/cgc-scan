package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func stateDoc(root string) *report.Document {
	fp := strings.Repeat("a", 32)
	fixed := "v0.41.0"
	direct := true
	doc := &report.Document{
		Run: report.Run{
			ID: "20261030T000000Z-aaaa", FinishedAt: "2026-10-30T00:00:01Z",
			DurationMS: 10, CLIVersion: "0.1.0",
		},
		Target: report.Target{Root: root, LocalID: report.LocalID(root), Units: []report.UnitInfo{
			{ID: "project", Path: ".", Kind: "repository"},
		}},
		Coverage: report.Coverage{
			Scope: report.Scope{Root: root}, Exclusions: []report.ExclusionReport{},
			NotAnalyzed: []report.NotAnalyzedReport{}, Units: []report.UnitCoverage{
				{ID: "project", Path: ".", Status: "completed", Engines: []report.EngineState{{ID: "trivy", Status: "completed"}}},
			},
			Limitations: []string{},
		},
		Tools: report.Tools{Engines: []report.EngineReport{
			{ID: "trivy", Version: "0.76.1", Status: "completed", Mode: "global", Units: []report.EngineState{{ID: "project", Status: "completed", Findings: 1}}},
		}},
		Isolation:  report.Isolation{Level: "configured"},
		Validation: report.Validation{Recipes: []report.Recipe{}, Unresolved: []report.Unresolved{}},
		Findings: []normalize.Finding{{
			Fingerprint: fp, Kind: normalize.KindVulnerability, Title: "x/text infinite loop",
			Severity:     normalize.SeverityInfo{Original: "HIGH", Normalized: normalize.SeverityHigh, Source: "trivy"},
			Sources:      []normalize.SourceRef{{Engine: "trivy", Version: "0.76.1"}},
			Locations:    []normalize.Location{{Path: "go.mod"}},
			Package:      &normalize.PackageRef{Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.0", FixedVersion: &fixed, Direct: &direct},
			Descriptions: []normalize.Description{{Text: "descripción larga", Source: "trivy"}},
			References:   []string{"https://example.test/CVE"},
			Evidence:     normalize.Evidence{Redacted: true},
			Policy:       normalize.FindingPolicy{Status: "active"},
		}},
		RemediationGroups: []report.RemediationGroup{{
			ID: "rg-go-golang.org/x/text", Kind: "dependency_upgrade", Unit: "project",
			Fixes: []string{fp}, MaxSeverity: normalize.SeverityHigh, BreakingRisk: "minor",
			Commands: report.GroupCommands{Apply: "go get golang.org/x/text@v0.41.0 && go mod tidy", Origin: "cgc-scan"},
			Verification: report.GroupVerification{
				Status: "ready", Recipes: []normalize.VerificationRecipe{}, Missing: []string{},
				Verify: "cgc-scan verify rg-go-golang.org/x/text",
			},
		}},
		NextActions: []report.NextAction{{Action: "apply_group", Group: "rg-go-golang.org/x/text"}},
		Policy:      report.Policy{FailOn: "high", Exceptions: []report.ExceptionReport{}},
		Errors:      []report.Error{},
	}
	doc.Normalize()
	return doc
}

func seedState(t *testing.T, app *App, root string) *projectstate.Store {
	t.Helper()
	store, err := projectstate.Open(app.Paths, root)
	if err != nil {
		t.Fatal(err)
	}
	doc := stateDoc(root)
	if err := store.SaveLatest(doc); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveIndex(projectstate.BuildIndex(doc)); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStatusReadsSavedState(t *testing.T) {
	app, stdout, stderr := newTestApp(t)
	root := t.TempDir()
	seedState(t, app, root)
	if code := app.Execute(context.Background(), []string{"status", root, "--format", "json"}); code != 0 {
		t.Fatalf("código = %d: %s", code, stderr.String())
	}
	var got StatusDocument
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Available || got.RunID != "20261030T000000Z-aaaa" {
		t.Fatalf("estado = %+v", got)
	}
	if got.Counts.Total != 1 || got.Counts.BySeverity["high"] != 1 || got.Groups != 1 {
		t.Fatalf("recuentos = %+v", got.Counts)
	}
	if !strings.Contains(got.ReportPath, "latest.json") {
		t.Fatalf("ruta = %q", got.ReportPath)
	}
}

func TestStatusWithoutReportIsIncomplete(t *testing.T) {
	app, _, _ := newTestApp(t)
	if code := app.Execute(context.Background(), []string{"status", t.TempDir(), "--format", "json"}); code != 3 {
		t.Fatalf("código = %d, want 3", code)
	}
}

func TestExplainFingerprintAndGroup(t *testing.T) {
	app, stdout, stderr := newTestApp(t)
	root := t.TempDir()
	seedState(t, app, root)
	fp := strings.Repeat("a", 32)
	if code := app.Execute(context.Background(), []string{"explain", fp, root, "--format", "json"}); code != 0 {
		t.Fatalf("código = %d: %s", code, stderr.String())
	}
	var got ExplainDocument
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Finding == nil || got.Finding.Fingerprint != fp {
		t.Fatalf("hallazgo = %+v", got.Finding)
	}
	if len(got.Finding.Descriptions) != 1 || len(got.Finding.References) != 1 {
		t.Fatal("explain no incluyó el detalle completo")
	}
	if got.Group == nil || got.Group.ID != "rg-go-golang.org/x/text" {
		t.Fatalf("grupo = %+v", got.Group)
	}

	stdout.Reset()
	if code := app.Execute(context.Background(), []string{"explain", "rg-go-golang.org/x/text", root, "--format", "json"}); code != 0 {
		t.Fatalf("código grupo = %d: %s", code, stderr.String())
	}
	var group ExplainDocument
	if err := json.Unmarshal(stdout.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	if group.Group == nil || len(group.Findings) != 1 {
		t.Fatalf("grupo = %+v", group)
	}
}

func TestExplainUnknownSelectorIsUsageError(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := t.TempDir()
	seedState(t, app, root)
	if code := app.Execute(context.Background(), []string{"explain", "no-existe", root}); code != 2 {
		t.Fatalf("código = %d, want 2", code)
	}
}

func TestCompareBaseline(t *testing.T) {
	app, stdout, stderr := newTestApp(t)
	root := t.TempDir()
	store := seedState(t, app, root)
	if err := store.SaveBaseline(stateDoc(root)); err != nil {
		t.Fatal(err)
	}
	changed := stateDoc(root)
	changed.Run.ID = "20261030T000100Z-bbbb"
	changed.Findings = append(changed.Findings, normalize.Finding{
		Fingerprint: strings.Repeat("b", 32), Kind: normalize.KindCode, Title: "nuevo",
		Severity:  normalize.SeverityInfo{Normalized: normalize.SeverityMedium, Source: "eslint"},
		Sources:   []normalize.SourceRef{{Engine: "eslint"}},
		Locations: []normalize.Location{{Path: "src/a.js"}},
		Policy:    normalize.FindingPolicy{Status: "active"},
	})
	changed.Normalize()
	if err := store.SaveLatest(changed); err != nil {
		t.Fatal(err)
	}
	if code := app.Execute(context.Background(), []string{"compare", "--baseline", root, "--format", "json"}); code != 0 {
		t.Fatalf("código = %d: %s", code, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got["new"].([]any)) != 1 {
		t.Fatalf("delta = %+v", got)
	}
}

func TestBaselineSetAndShow(t *testing.T) {
	app, stdout, stderr := newTestApp(t)
	root := t.TempDir()
	seedState(t, app, root)
	if code := app.Execute(context.Background(), []string{"baseline", "set", root, "--format", "json"}); code != 0 {
		t.Fatalf("código set = %d: %s", code, stderr.String())
	}
	stdout.Reset()
	if code := app.Execute(context.Background(), []string{"baseline", "show", root, "--format", "json"}); code != 0 {
		t.Fatalf("código show = %d: %s", code, stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["available"] != true || got["run_id"] != "20261030T000000Z-aaaa" {
		t.Fatalf("línea base = %+v", got)
	}
}

func TestPlanFromSavedState(t *testing.T) {
	app, stdout, stderr := newTestApp(t)
	root := t.TempDir()
	seedState(t, app, root)
	if code := app.Execute(context.Background(), []string{"plan", root, "--format", "json"}); code != 0 {
		t.Fatalf("código = %d: %s", code, stderr.String())
	}
	var got PlanDocument
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Groups) != 1 || got.Groups[0].ID != "rg-go-golang.org/x/text" {
		t.Fatalf("grupos = %+v", got.Groups)
	}
	if len(got.NextActions) == 0 {
		t.Fatal("faltan próximas acciones")
	}
	if !strings.HasSuffix(got.ReportPath, "latest.json") {
		t.Fatalf("ruta = %q", got.ReportPath)
	}
}

func TestCompareWithoutBaselineIsIncomplete(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := t.TempDir()
	seedState(t, app, root)
	if code := app.Execute(context.Background(), []string{"compare", "--baseline", root}); code != 3 {
		t.Fatalf("código = %d, want 3", code)
	}
}
