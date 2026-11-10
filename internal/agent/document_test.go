package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/testutil/golden"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

func sampleDoc() *report.Document {
	direct := true
	score := 87
	rank := 1
	doc := &report.Document{
		Run: report.Run{
			ID: "20261030T000000Z-abcd", FinishedAt: "2026-10-30T00:00:01Z",
			DurationMS: 1200, CLIVersion: "0.1.0",
		},
		Target: report.Target{Root: "/p", LocalID: "local:p", Units: []report.UnitInfo{
			{ID: "project", Path: ".", Kind: "repository"},
		}},
		Coverage: report.Coverage{
			Partial: false, Units: []report.UnitCoverage{{ID: "project", Path: ".", Status: "completed", Engines: []report.EngineState{}}},
			Limitations: []string{},
		},
		Findings: []normalize.Finding{{
			Fingerprint: strings.Repeat("a", 32), Kind: normalize.KindVulnerability,
			Title:     "x/text infinite loop",
			Severity:  normalize.SeverityInfo{Original: "HIGH", Normalized: normalize.SeverityHigh, Source: "trivy"},
			Sources:   []normalize.SourceRef{{Engine: "trivy"}},
			Locations: []normalize.Location{{Path: "go.mod"}},
			Package: &normalize.PackageRef{
				Ecosystem: "Go", Name: "golang.org/x/text", Version: "v0.3.0",
				FixedVersion: ptr("v0.41.0"), Direct: &direct,
			},
			Priority: &normalize.Priority{Score: &score, Rank: &rank, Factors: []string{"high", "fix_available", "direct"}},
			Policy:   normalize.FindingPolicy{Status: "active"},
		}},
		RemediationGroups: []report.RemediationGroup{{
			ID: "rg-go-golang.org/x/text", Kind: "dependency_upgrade", Unit: "project",
			Package: &report.GroupPackage{Ecosystem: "Go", Name: "golang.org/x/text", From: "v0.3.0", To: "v0.41.0"},
			Fixes:   []string{strings.Repeat("a", 32)}, MaxSeverity: normalize.SeverityHigh,
			PriorityScore: 87, BreakingRisk: "minor", Direct: &direct,
			Commands: report.GroupCommands{Apply: "go get golang.org/x/text@v0.41.0 && go mod tidy", Origin: "cgc-scan"},
			Verification: report.GroupVerification{
				Status: "ready", Recipes: []normalize.VerificationRecipe{
					{Unit: "project", Kind: "test", Command: "go test ./...", Workdir: ".", Origin: "user"},
				}, Missing: []string{}, Verify: "cgc-scan verify rg-go-golang.org/x/text",
			},
		}},
		NextActions: []report.NextAction{{
			Action: "apply_group", Group: "rg-go-golang.org/x/text", Fixes: 1,
			Command: "go get golang.org/x/text@v0.41.0 && go mod tidy", Reason: "actualizar golang.org/x/text a v0.41.0",
		}},
		Delta: &report.Delta{
			BaselineRun: "base", CurrentRun: "cur", CoverageComparable: true,
			New:        []report.DeltaEntry{{Fingerprint: strings.Repeat("a", 32), Kind: normalize.KindVulnerability, Title: "x", Severity: normalize.SeverityHigh}},
			Persistent: []report.DeltaEntry{}, Resolved: []report.DeltaEntry{}, NotEvaluated: []report.DeltaEntry{},
		},
		Errors: []report.Error{},
	}
	doc.Normalize()
	return doc
}

func ptr[T any](v T) *T { return &v }

func TestBuildCompactDocument(t *testing.T) {
	doc := sampleDoc()
	got := Build(doc, Options{ExitCode: 1, ReportPath: "/cache/latest.json", BaselineCreated: true})
	if got.SchemaVersion != version.AgentSchemaVersion {
		t.Fatalf("schema = %q", got.SchemaVersion)
	}
	if got.Summary.Status != "findings" || got.Summary.ExitCode != 1 {
		t.Fatalf("summary = %+v", got.Summary)
	}
	if got.Summary.Counts.Findings != 1 || got.Summary.Counts.High != 1 || got.Summary.Counts.Groups != 1 {
		t.Fatalf("counts = %+v", got.Summary.Counts)
	}
	if got.Summary.Counts.New != 1 || !got.Run.BaselineCreated {
		t.Fatalf("delta/base = %+v %+v", got.Summary.Counts, got.Run)
	}
	data, err := got.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data); err != nil {
		t.Fatalf("el documento de agente no valida: %v", err)
	}
	s := string(data)
	for _, forbidden := range []string{"description", "references", "evidence", "snippet"} {
		if strings.Contains(s, `"`+forbidden+`"`) {
			t.Errorf("el documento compacto incluye %q", forbidden)
		}
	}
	if strings.Contains(s, `"sources"`) {
		t.Errorf("el documento compacto incluye sources")
	}
	golden.Assert(t, "testdata", "agent-xtext.golden.json", data)
}

func TestBuildTruncatesExplicitly(t *testing.T) {
	doc := sampleDoc()
	second := doc.RemediationGroups[0]
	second.ID = "rg-go-other"
	doc.RemediationGroups = append(doc.RemediationGroups, second)
	doc.NextActions = append(doc.NextActions, report.NextAction{Action: "apply_group", Group: second.ID})
	got := Build(doc, Options{ExitCode: 1, MaxGroups: 1})
	if !got.Summary.Truncated || got.Summary.GroupsTotal != 2 || got.Summary.GroupsShown != 1 {
		t.Fatalf("resumen = %+v", got.Summary)
	}
	if len(got.RemediationGroups) != 1 || got.RemediationGroups[0].ID != "rg-go-golang.org/x/text" {
		t.Fatalf("grupos = %+v", got.RemediationGroups)
	}
	for _, a := range got.NextActions {
		if a.Group == "rg-go-other" {
			t.Fatal("se incluyó una acción de un grupo truncado")
		}
	}
	data, _ := json.Marshal(got)
	if !strings.Contains(string(data), `"truncated":true`) {
		t.Fatal("el truncamiento no se declara")
	}
}

func TestBuildBlockedReasons(t *testing.T) {
	doc := sampleDoc()
	doc.Findings = []normalize.Finding{}
	doc.RemediationGroups = []report.RemediationGroup{}
	doc.NextActions = []report.NextAction{}
	doc.Validation.Unresolved = []report.Unresolved{{Unit: "backoffice", Missing: []string{"test", "build"}}}
	doc.Errors = []report.Error{{Code: "requirement_missing", Scope: "psalm:backoffice", Message: "falta composer install"}}
	got := Build(doc, Options{ExitCode: 0})
	if got.Summary.Status != "blocked" {
		t.Fatalf("estado = %q", got.Summary.Status)
	}
	if len(got.Blocked) != 2 {
		t.Fatalf("bloqueos = %+v", got.Blocked)
	}
	var tool *Blocked
	for i := range got.Blocked {
		if got.Blocked[i].Engine != "" {
			tool = &got.Blocked[i]
		}
	}
	if tool == nil || tool.Engine != "psalm" || tool.Unit != "backoffice" {
		t.Fatalf("bloqueo de herramienta = %+v", got.Blocked)
	}
}

func TestPublicAgentSchemaMatchesEmbedded(t *testing.T) {
	public, err := os.ReadFile(filepath.Join("..", "..", "schemas", "agent.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(public)) != strings.TrimSpace(string(SchemaJSON)) {
		t.Fatal("schemas/agent.schema.json y el esquema embebido divergen")
	}
}

func TestMinSeverityIsViewOnlyAndDeclared(t *testing.T) {
	doc := sampleDoc()
	second := doc.RemediationGroups[0]
	second.ID = "rg-low"
	second.MaxSeverity = normalize.SeverityLow
	doc.RemediationGroups = append(doc.RemediationGroups, second)
	doc.NextActions = append(doc.NextActions, report.NextAction{Action: "apply_group", Group: second.ID})
	got := Build(doc, Options{ExitCode: 1, MinSeverity: normalize.SeverityHigh})
	if got.Summary.Counts.Findings != 1 {
		t.Fatalf("el filtro cambió los recuentos del reporte: %+v", got.Summary.Counts)
	}
	if got.Summary.GroupsFiltered != 1 || got.Summary.GroupsShown != 1 {
		t.Fatalf("resumen = %+v", got.Summary)
	}
	if got.Summary.Filter == nil || got.Summary.Filter.MinSeverity != normalize.SeverityHigh {
		t.Fatalf("filtro no declarado: %+v", got.Summary.Filter)
	}
	for _, a := range got.NextActions {
		if a.Group == "rg-low" {
			t.Fatal("se incluyó una acción de un grupo filtrado")
		}
	}
}
