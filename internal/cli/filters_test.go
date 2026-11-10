package cli

import (
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
)

func TestFilterEnginesByOnlyAndExplicitList(t *testing.T) {
	engines := []orchestrator.Engine{
		{ID: "trivy"}, {ID: "govulncheck"}, {ID: "eslint"}, {ID: "semgrep"},
	}
	kept, omitted := filterEngines(engines, scanOptions{Only: []string{"deps"}})
	if len(kept) != 2 || kept[0].ID != "trivy" || kept[1].ID != "govulncheck" || len(omitted) != 2 {
		t.Fatalf("kept=%v omitted=%v", kept, omitted)
	}
	kept, omitted = filterEngines(engines, scanOptions{Only: []string{"deps"}, Engines: []string{"trivy"}})
	if len(kept) != 1 || kept[0].ID != "trivy" || len(omitted) != 3 {
		t.Fatalf("intersección: kept=%v omitted=%v", kept, omitted)
	}
	if !restrictedScope(scanOptions{Only: []string{"deps"}}) || restrictedScope(scanOptions{}) {
		t.Fatal("restrictedScope incorrecto")
	}
}

func TestFilterFindingsByCategory(t *testing.T) {
	in := []normalize.Finding{
		{Kind: normalize.KindVulnerability},
		{Kind: normalize.KindSecret},
		{Kind: normalize.KindCode},
		{Kind: normalize.KindMisconfig},
	}
	for _, tt := range []struct {
		cats []string
		want []normalize.Kind
	}{
		{[]string{"deps"}, []normalize.Kind{normalize.KindVulnerability}},
		{[]string{"secrets"}, []normalize.Kind{normalize.KindSecret}},
		{[]string{"code"}, []normalize.Kind{normalize.KindCode}},
		{[]string{"config"}, []normalize.Kind{normalize.KindMisconfig}},
		{[]string{"deps", "secrets"}, []normalize.Kind{normalize.KindVulnerability, normalize.KindSecret}},
	} {
		got := filterFindings(in, tt.cats)
		if len(got) != len(tt.want) {
			t.Fatalf("%v: %v", tt.cats, got)
		}
		for i := range got {
			if got[i].Kind != tt.want[i] {
				t.Fatalf("%v: %v", tt.cats, got)
			}
		}
	}
}
