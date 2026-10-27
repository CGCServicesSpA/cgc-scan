package policyfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
)

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func TestLoadValidPolicy(t *testing.T) {
	dir := writePolicy(t, `
fail_on = "critical"
exclude = ["docs/**", "**/fixtures/**"]

[[exception]]
fingerprint = "0123456789abcdef0123456789abcdef"
reason = "No alcanzable"
owner = "equipo-seguridad"
expires = 2027-01-31
`)
	p, err := Load(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Present || p.FailOn != normalize.SeverityCritical {
		t.Fatalf("política = %+v", p)
	}
	if len(p.Exclude) != 2 || p.Exclude[0] != "docs/**" {
		t.Fatalf("exclusiones = %v", p.Exclude)
	}
	if len(p.Exceptions) != 1 || !p.Exceptions[0].Effective {
		t.Fatalf("excepciones = %+v", p.Exceptions)
	}
	if p.Exceptions[0].Expires != "2027-01-31" {
		t.Errorf("vencimiento = %q", p.Exceptions[0].Expires)
	}
	if len(p.Issues) != 0 {
		t.Fatalf("problemas = %+v", p.Issues)
	}
}

func TestLoadIgnoresForbiddenKeys(t *testing.T) {
	dir := writePolicy(t, `
fail_on = "critical"
trivy_mode = "global"
semgrep_enabled = true
recipes = [{ project = "/x" }]
network = "host"

[[exception]]
fingerprint = "f"
reason = "r"
owner = "o"
`)
	p, err := Load(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Issues) < 4 {
		t.Fatalf("no se registraron las claves ignoradas: %+v", p.Issues)
	}
	if p.FailOn != normalize.SeverityCritical {
		t.Fatal("se perdió la parte válida")
	}
	// La excepción sin expires se rechaza.
	if len(p.Exceptions) != 0 {
		t.Fatalf("se aceptó una excepción sin vencimiento: %+v", p.Exceptions)
	}
}

func TestLoadIgnoresMalformedTOML(t *testing.T) {
	dir := writePolicy(t, "esto no es = [toml")
	p, err := Load(dir, now)
	if err != nil {
		t.Fatalf("un TOML inválido no debe romper el escaneo: %v", err)
	}
	if len(p.Issues) != 1 || p.Issues[0].Code != "policy_invalid_toml" {
		t.Fatalf("problemas = %+v", p.Issues)
	}
}

func TestLoadRejectsBadExcludes(t *testing.T) {
	dir := writePolicy(t, `exclude = ["/abs/**", "../fuera/**", "", "docs/[", "ok/**"]`)
	p, err := Load(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Exclude) != 1 || p.Exclude[0] != "ok/**" {
		t.Fatalf("exclusiones = %v", p.Exclude)
	}
	if len(p.Issues) != 4 {
		t.Fatalf("problemas = %+v", p.Issues)
	}
}

func TestExpiredExceptionIsIneffective(t *testing.T) {
	dir := writePolicy(t, `
[[exception]]
fingerprint = "0123456789abcdef0123456789abcdef"
reason = "vieja"
owner = "equipo"
expires = 2026-01-01
`)
	p, err := Load(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Exceptions) != 1 || p.Exceptions[0].Effective {
		t.Fatalf("excepción = %+v", p.Exceptions)
	}
}

func TestEffectiveFailOnOnlyHardens(t *testing.T) {
	p := Policy{FailOn: normalize.SeverityCritical}
	got, issues := EffectiveFailOn(false, "", p, normalize.SeverityHigh)
	if got != normalize.SeverityCritical || len(issues) != 0 {
		t.Fatalf("got=%s issues=%+v", got, issues)
	}

	weak := Policy{FailOn: normalize.SeverityLow}
	got, issues = EffectiveFailOn(false, "", weak, normalize.SeverityHigh)
	if got != normalize.SeverityHigh {
		t.Fatalf("se permitió debilitar el umbral: %s", got)
	}
	if len(issues) != 1 || issues[0].Code != "policy_weakened_fail_on" {
		t.Fatalf("issues = %+v", issues)
	}

	got, _ = EffectiveFailOn(true, "low", p, normalize.SeverityHigh)
	if got != normalize.SeverityLow {
		t.Fatalf("el flag debe tener precedencia: %s", got)
	}
}
