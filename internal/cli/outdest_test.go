package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitInitProject(t *testing.T) string {
	t.Helper()
	root := auditProject(t)
	cmd := exec.Command("git", "-C", root, "-c", "user.email=t@t", "-c", "user.name=t",
		"-c", "commit.gpgsign=false", "init", "-q")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestOutDestinationExternalAllowed(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	out := filepath.Join(t.TempDir(), "run")
	if code, outS, errOut := auditRun(t, app, "audit", "init", root, "--out", out, "--format", "json"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, outS, errOut)
	}
}

func TestOutDestinationGitIgnoredAllowed(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := gitInitProject(t)
	// El destino interno está efectivamente ignorado por Git.
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("auditoria/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "auditoria")
	if code, outS, errOut := auditRun(t, app, "audit", "init", root, "--out", out, "--format", "json"); code != 0 {
		t.Fatalf("init interno ignorado = %d: %s %s", code, outS, errOut)
	}
}

func TestOutDestinationGitVisibleRejectedBeforeArtifacts(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := gitInitProject(t)
	out := filepath.Join(root, "auditoria")
	code, _, errOut := auditRun(t, app, "audit", "init", root, "--out", out, "--format", "json")
	if code != 2 || !strings.Contains(errOut, "no lo ignora") {
		t.Fatalf("init interno visible = %d: %s; se esperaba rechazo", code, errOut)
	}
	// Un rechazo no deja una corrida parcial ni crea artefactos.
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("el rechazo creó el destino: %v", err)
	}
}

func TestOutDestinationWithoutGitRejected(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t) // sin Git
	out := filepath.Join(root, "auditoria")
	code, _, errOut := auditRun(t, app, "audit", "init", root, "--out", out, "--format", "json")
	if code != 2 || !strings.Contains(errOut, "no se puede verificar") {
		t.Fatalf("init interno sin Git = %d: %s; se esperaba rechazo", code, errOut)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("el rechazo creó el destino: %v", err)
	}
}

func TestOutDestinationSymlinkEscapeIsExternal(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := gitInitProject(t)
	outside := t.TempDir()
	// Un enlace dentro del repositorio apunta fuera: el destino resuelto es
	// externo y honesto.
	if err := os.Symlink(outside, filepath.Join(root, "enlace-auditoria")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "enlace-auditoria", "run")
	if code, outS, errOut := auditRun(t, app, "audit", "init", root, "--out", out, "--format", "json"); code != 0 {
		t.Fatalf("init por enlace = %d: %s %s", code, outS, errOut)
	}
	if _, err := os.Stat(filepath.Join(outside, "run", "state.json")); err != nil {
		t.Fatalf("la corrida no quedó en el destino externo: %v", err)
	}
}

func TestOutCheckDoesNotModifyGitignore(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := gitInitProject(t)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("auditoria/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	// Un rechazo y una corrida permitida no modifican .gitignore.
	out := filepath.Join(root, "otra")
	code, _, _ := auditRun(t, app, "audit", "init", root, "--out", out)
	if code != 2 {
		t.Fatalf("interno visible = %d, want 2", code)
	}
	allowed := filepath.Join(root, "auditoria")
	if code, _, _ := auditRun(t, app, "audit", "init", root, "--out", allowed); code != 0 {
		t.Fatalf("interno ignorado = %d, want 0", code)
	}
	after, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("la comprobación modificó .gitignore")
	}
}
