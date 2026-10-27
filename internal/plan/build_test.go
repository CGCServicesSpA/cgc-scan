package plan

import (
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

func unitsFixture() discovery.Result {
	return discovery.Result{
		Root: "/repo",
		Units: []discovery.Unit{
			{ID: "project", Path: ".", Kind: "repository"},
			{ID: "a", Path: "services/a", Kind: "module", Languages: []discovery.Language{discovery.Go}},
			{ID: "b", Path: "services/b", Kind: "module", Languages: []discovery.Language{discovery.Python}},
			{ID: "docs", Path: "docs/examples", Kind: "directory"},
		},
		Exclusions: []discovery.Exclusion{
			{Pattern: "**/node_modules/**", Origin: discovery.OriginIntrinsic},
			{Pattern: "docs/**", Origin: discovery.OriginCLI},
		},
		Partial: true,
	}
}

func TestBuildRequestsAllEngines(t *testing.T) {
	p := Build(unitsFixture(), []string{"trivy", "eslint"})
	if len(p.Units) != 4 {
		t.Fatalf("unidades = %d", len(p.Units))
	}
	for _, u := range p.Units {
		if len(u.Engines) != 2 {
			t.Fatalf("motores = %d", len(u.Engines))
		}
		for _, e := range u.Engines {
			if e.Status != StatusRequested {
				t.Errorf("estado = %q", e.Status)
			}
		}
	}
}

func TestApplySelectionExcludesAndMarksNotAnalyzed(t *testing.T) {
	p := Build(unitsFixture(), []string{"trivy"})
	p.Include = []string{"services/**"}
	ApplySelection(&p)
	if !p.Partial {
		t.Fatal("--include debe marcar parcial")
	}
	var kept []string
	for _, u := range p.Units {
		kept = append(kept, u.Unit.ID)
	}
	if len(kept) != 2 || kept[0] != "a" || kept[1] != "b" {
		t.Fatalf("unidades conservadas = %v", kept)
	}
	if len(p.NotAnalyzed) != 2 {
		t.Fatalf("no analizadas = %+v", p.NotAnalyzed)
	}
}

func TestApplySelectionExclusionsOverrideIncludes(t *testing.T) {
	p := Build(unitsFixture(), []string{"trivy"})
	p.Include = []string{"services/**", "docs/**"}
	ApplySelection(&p)
	for _, u := range p.Units {
		if u.Unit.ID == "docs" {
			t.Fatal("una inclusión reactivó contenido excluido")
		}
	}
}

func TestUnitStatus(t *testing.T) {
	p := Build(unitsFixture(), []string{"trivy", "eslint"})
	if got := p.UnitStatus("a"); got != StatusRequested {
		t.Fatalf("estado inicial = %q", got)
	}
	p.SetEngineStatus("a", "trivy", StatusCompleted, "")
	p.SetEngineStatus("a", "eslint", StatusCompleted, "")
	if got := p.UnitStatus("a"); got != StatusCompleted {
		t.Fatalf("estado = %q", got)
	}
	p.SetEngineStatus("a", "eslint", StatusFailed, "boom")
	if got := p.UnitStatus("a"); got != StatusFailed {
		t.Fatalf("estado = %q", got)
	}
}
