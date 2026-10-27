package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

func newTestApp(t *testing.T) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	paths := platform.Paths{
		ConfigDir: filepath.Join(dir, "config"),
		DataDir:   filepath.Join(dir, "data"),
		CacheDir:  filepath.Join(dir, "cache"),
	}
	var stdout, stderr bytes.Buffer
	app, err := New(&stdout, &stderr,
		WithPaths(paths),
		WithTTY(false),
		WithNow(func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app, &stdout, &stderr
}

func TestUnknownFlagIsUsageError(t *testing.T) {
	app, _, stderr := newTestApp(t)
	if code := app.Execute(context.Background(), []string{"scan", "--no-existe"}); code != 2 {
		t.Fatalf("código = %d, want 2 (stderr: %s)", code, stderr.String())
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	app, _, _ := newTestApp(t)
	if code := app.Execute(context.Background(), []string{"analizar"}); code != 2 {
		t.Fatalf("código = %d, want 2", code)
	}
}

func TestUnsupportedAIFlagsAreUsageErrors(t *testing.T) {
	app, _, _ := newTestApp(t)
	for _, args := range [][]string{
		{"scan", "--ai"},
		{"analyze", "."},
	} {
		if code := app.Execute(context.Background(), args); code != 2 {
			t.Errorf("%v: código = %d, want 2", args, code)
		}
	}
}

func TestInvalidEnumIsUsageError(t *testing.T) {
	app, _, _ := newTestApp(t)
	cases := [][]string{
		{"scan", "--format", "xml"},
		{"scan", "--fail-on", "critico"},
		{"scan", "--trivy-mode", "podman"},
		{"scan", "--require-isolation", "sandbox"},
		{"scan", "--timeout", "0s"},
		{"scan", "--concurrency", "-1"},
		{"setup", "--trivy-mode", "podman"},
		{"setup", "--semgrep", "maybe"},
		{"doctor", "--format", "xml"},
		{"compare", "a.json", "b.json", "--format", "xml"},
		{"recipes", "--set", "x.toml", "--clear"},
		{"scan", "a", "b"},
	}
	for _, args := range cases {
		if code := app.Execute(context.Background(), args); code != 2 {
			t.Errorf("%v: código = %d, want 2", args, code)
		}
	}
}

func TestQuietAndVerboseConflict(t *testing.T) {
	app, _, _ := newTestApp(t)
	if code := app.Execute(context.Background(), []string{"scan", "--quiet", "--verbose"}); code != 2 {
		t.Fatalf("código = %d, want 2", code)
	}
}

func TestSkeletonCommandsReturnIncomplete(t *testing.T) {
	app, _, stderr := newTestApp(t)
	for _, args := range [][]string{
		{"setup", "--trivy-mode", "docker", "--non-interactive"},
		{"doctor"},
		{"scan", "."},
		{"compare", "a.json", "b.json"},
		{"update-db"},
		{"recipes"},
	} {
		if code := app.Execute(context.Background(), args); code != 3 {
			t.Errorf("%v: código = %d, want 3", args, code)
		}
	}
	if !strings.Contains(stderr.String(), "no está implementado") {
		t.Errorf("stderr no explica el bloqueo: %q", stderr.String())
	}
}

func TestVersionReportsCLIAndSchema(t *testing.T) {
	app, stdout, _ := newTestApp(t)
	if code := app.Execute(context.Background(), []string{"--version"}); code != 0 {
		t.Fatalf("código = %d, want 0", code)
	}
	out := stdout.String()
	for _, want := range []string{version.Name, version.SchemaVersion, "esquema"} {
		if !strings.Contains(out, want) {
			t.Errorf("--version no contiene %q: %q", want, out)
		}
	}
}

func TestHelpExitsZero(t *testing.T) {
	app, stdout, _ := newTestApp(t)
	if code := app.Execute(context.Background(), []string{"help"}); code != 0 {
		t.Fatalf("código = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "scan") {
		t.Errorf("la ayuda no lista los comandos: %q", stdout.String())
	}
}

func TestColorDisabledWithoutTTYOrWithNoColor(t *testing.T) {
	app, _, _ := newTestApp(t)
	if app.ColorEnabled() {
		t.Error("color habilitado sin TTY")
	}
	app.IsTTY = true
	t.Setenv("NO_COLOR", "1")
	if app.ColorEnabled() {
		t.Error("color habilitado con NO_COLOR")
	}
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	if !app.ColorEnabled() {
		t.Error("color deshabilitado con TTY y sin NO_COLOR")
	}
}
