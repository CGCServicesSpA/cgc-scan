package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalReport = `{
  "schema_version": "1.0.0",
  "run": {
    "id": "20261027T000000Z-abc123",
    "started_at": "2026-10-27T00:00:00Z",
    "finished_at": "2026-10-27T00:00:01Z",
    "duration_ms": 1000,
    "cli_version": "0.1.0",
    "cli_commit": "deadbeef",
    "arguments": {},
    "config_origin": []
  },
  "target": {
    "root": "/tmp/proyecto",
    "local_id": "local:proyecto",
    "vcs": { "available": false },
    "units": []
  },
  "coverage": {
    "partial": false,
    "scope": { "root": "/tmp/proyecto", "include": [], "exclude": [] },
    "exclusions": [],
    "not_analyzed": [],
    "units": [],
    "limitations": []
  },
  "tools": { "engines": [] },
  "isolation": { "level": "configured", "verified_by": "" },
  "validation": { "recipes": [], "unresolved": [] },
  "findings": [],
  "policy": {
    "fail_on": "high",
    "violated": false,
    "unknown_counts": true,
    "exceptions": [],
    "suppressed_count": 0
  },
  "errors": []
}`

func TestSchemaCompilesAndValidatesMinimalReport(t *testing.T) {
	if _, err := Schema(); err != nil {
		t.Fatalf("Schema: %v", err)
	}
	if err := Validate([]byte(minimalReport)); err != nil {
		t.Fatalf("el reporte mínimo no valida: %v", err)
	}
}

func TestSchemaRejectsInvalidDocuments(t *testing.T) {
	var base map[string]any
	if err := json.Unmarshal([]byte(minimalReport), &base); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"falta schema_version", func(m map[string]any) { delete(m, "schema_version") }},
		{"falta coverage.partial", func(m map[string]any) {
			delete(m["coverage"].(map[string]any), "partial")
		}},
		{"origen de exclusión desconocido", func(m map[string]any) {
			m["coverage"].(map[string]any)["exclusions"] = []any{
				map[string]any{"pattern": "docs/**", "origin": "porque-si"},
			}
		}},
		{"duración negativa", func(m map[string]any) {
			m["run"].(map[string]any)["duration_ms"] = -1
		}},
		{"severidad inválida", func(m map[string]any) {
			m["findings"] = []any{map[string]any{
				"fingerprint": "0123456789abcdef0123456789abcdef",
				"kind":        "vulnerability",
				"title":       "x",
				"severity": map[string]any{
					"original": "HIGH", "normalized": "altisima", "source": "trivy",
				},
				"sources": []any{map[string]any{"engine": "trivy"}},
			}}
		}},
		{"campo desconocido en la raíz", func(m map[string]any) { m["extra"] = true }},
		{"nivel de aislamiento inválido", func(m map[string]any) {
			m["isolation"].(map[string]any)["level"] = "sandbox"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc map[string]any
			raw, _ := json.Marshal(base)
			_ = json.Unmarshal(raw, &doc)
			tt.mutate(doc)
			out, _ := json.Marshal(doc)
			if err := Validate(out); err == nil {
				t.Fatal("el esquema aceptó un documento inválido")
			}
		})
	}
}

func TestSchemaAcceptsFindingAndCoveragePartial(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(minimalReport), &doc); err != nil {
		t.Fatal(err)
	}
	cov := doc["coverage"].(map[string]any)
	cov["partial"] = true
	cov["exclusions"] = []any{
		map[string]any{"pattern": "node_modules/**", "origin": "intrinsic"},
		map[string]any{"pattern": "docs/**", "origin": "user", "reason": "ejemplos"},
	}
	cov["not_analyzed"] = []any{
		map[string]any{"unit": "svc/api", "path": "svc/api", "reason": "excluida por el usuario", "patterns": []any{"docs/**"}},
	}
	doc["findings"] = []any{map[string]any{
		"fingerprint": "0123456789abcdef0123456789abcdef",
		"kind":        "vulnerability",
		"title":       "CVE en x/text",
		"severity": map[string]any{
			"original": "HIGH", "normalized": "high", "source": "trivy",
		},
		"ids":       []any{map[string]any{"type": "CVE", "value": "CVE-2021-0000"}},
		"locations": []any{map[string]any{"path": "go.mod", "start_line": 5}},
		"sources":   []any{map[string]any{"engine": "trivy", "version": "0.76.1"}},
		"package": map[string]any{
			"ecosystem": "Go", "name": "golang.org/x/text", "version": "v0.3.0", "fixed_version": "v0.3.7",
		},
		"policy": map[string]any{"status": "active"},
		"priority": map[string]any{
			"cvss_score": 7.5, "cvss_vector": "CVSS:3.1/...", "epss": 0.1, "kev": true, "reachable": nil,
		},
	}}
	out, _ := json.Marshal(doc)
	if err := Validate(out); err != nil {
		t.Fatalf("reporte con hallazgo no valida: %v", err)
	}
}

func TestPublicSchemaMatchesEmbedded(t *testing.T) {
	public, err := os.ReadFile(filepath.Join("..", "..", "schemas", "report.schema.json"))
	if err != nil {
		t.Fatalf("leer esquema público: %v", err)
	}
	if strings.TrimSpace(string(public)) != strings.TrimSpace(string(SchemaJSON)) {
		t.Fatal("schemas/report.schema.json y el esquema embebido divergen")
	}
}

func TestValidateRejectsNonJSON(t *testing.T) {
	if err := Validate([]byte("no soy json")); err == nil {
		t.Fatal("Validate aceptó texto que no es JSON")
	}
}
