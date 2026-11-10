//go:build integration

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/agent"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// TestAgentFlowIntegration recorre el flujo real del agente: one-shot, caché,
// estado, plan, explain y verify contra Trivy y su base local. Requiere:
//
//	CGC_SCAN_TRIVY_BIN=/ruta/trivy CGC_SCAN_TRIVY_CACHE=/ruta/cache
func TestAgentFlowIntegration(t *testing.T) {
	bin := os.Getenv("CGC_SCAN_TRIVY_BIN")
	cache := os.Getenv("CGC_SCAN_TRIVY_CACHE")
	if bin == "" || cache == "" {
		t.Skip("define CGC_SCAN_TRIVY_BIN y CGC_SCAN_TRIVY_CACHE")
	}
	work := t.TempDir()
	fixture := filepath.Join(work, "proj")
	if err := os.MkdirAll(fixture, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, fixture)
	paths := platform.Paths{
		ConfigDir: filepath.Join(work, "cfg"),
		DataDir:   filepath.Join(work, "data"),
		CacheDir:  filepath.Join(work, "cache"),
	}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	engineDir := paths.EngineDir("trivy", "0.76.1")
	if err := os.MkdirAll(engineDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(bin, filepath.Join(engineDir, "trivy")); err != nil {
		t.Fatal(err)
	}
	trivyCache := paths.TrivyCacheDir()
	if err := os.MkdirAll(trivyCache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cache, "db"), filepath.Join(trivyCache, "db")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cache, "policy")); err == nil {
		if err := os.Symlink(filepath.Join(cache, "policy"), filepath.Join(trivyCache, "policy")); err != nil {
			t.Fatal(err)
		}
	}
	if goDB := os.Getenv("CGC_SCAN_GO_VULNDB"); goDB != "" {
		if err := os.Symlink(goDB, filepath.Join(paths.CacheDir, "go-vulndb")); err != nil {
			t.Fatal(err)
		}
	}
	cfg := "trivy_mode = 'global'\n[db]\nrefresh_after = '12h'\n"
	if err := os.WriteFile(paths.ConfigFile(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) ([]byte, int, string) {
		var stdout, stderr bytes.Buffer
		app, err := New(&stdout, &stderr, WithTTY(false), WithPaths(paths))
		if err != nil {
			t.Fatal(err)
		}
		code := app.Execute(context.Background(), args)
		return stdout.Bytes(), code, stderr.String()
	}

	out, code, errText := run("agent", fixture, "--offline", "--no-auto-install")
	if code != 1 {
		t.Fatalf("agent = %d: %s", code, errText)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if err := agent.Validate(out); err != nil {
		t.Fatalf("agent no valida contra agent-1.0.0: %v", err)
	}
	if doc["schema_version"] != "agent-1.0.0" {
		t.Fatalf("esquema = %v", doc["schema_version"])
	}
	groups := doc["remediation_groups"].([]any)
	var xt *map[string]any
	for _, g := range groups {
		m := g.(map[string]any)
		if m["id"] == "rg-go-golang.org/x/text" {
			xt = &m
		}
	}
	if xt == nil {
		t.Fatalf("falta el grupo x/text: %v", groups)
	}
	pkg := (*xt)["package"].(map[string]any)
	if pkg["to"] != "v0.41.0" || len((*xt)["fixes"].([]any)) != 5 {
		t.Fatalf("grupo x/text = %v", *xt)
	}

	// La repetición usa la caché por unidad y motor.
	if _, code, errText := run("agent", fixture, "--offline", "--no-auto-install"); code != 1 {
		t.Fatalf("segundo agent = %d: %s", code, errText)
	}
	latest, err := os.ReadFile(filepath.Join(paths.CacheDir, "projects",
		sanitizeID(report.LocalID(fixture)), "latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(latest); err != nil {
		t.Fatalf("latest inválido: %v", err)
	}
	var canonical map[string]any
	_ = json.Unmarshal(latest, &canonical)
	engines := canonical["tools"].(map[string]any)["engines"].([]any)
	foundHit := false
	for _, e := range engines {
		if e.(map[string]any)["cache"] == "hit" {
			foundHit = true
		}
	}
	if !foundHit {
		t.Fatalf("la repetición no declaró caché hit: %v", engines)
	}

	if _, code, errText := run("status", fixture, "--format", "json"); code != 0 {
		t.Fatalf("status = %d: %s", code, errText)
	}
	if _, code, errText := run("plan", fixture, "--format", "json"); code != 0 {
		t.Fatalf("plan = %d: %s", code, errText)
	}
	if _, code, errText := run("explain", "rg-go-golang.org/x/text", fixture, "--format", "json"); code != 0 {
		t.Fatalf("explain = %d: %s", code, errText)
	}
	if _, code, errText := run("verify", "rg-go-golang.org/x/text", fixture, "--format", "json"); code != 1 {
		t.Fatalf("verify sin parche = %d: %s", code, errText)
	}
}

func sanitizeID(id string) string {
	out := make([]rune, 0, len(id))
	for _, r := range id {
		switch r {
		case '/', '\\', ':', ' ':
			out = append(out, '_')
		default:
			out = append(out, r)
		}
	}
	return string(out)
}
