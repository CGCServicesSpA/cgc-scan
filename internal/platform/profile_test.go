package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureProfilePATHIsIdempotent(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(rc, []byte("alias ll='ls -l'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

	first, err := EnsureProfilePATH(home, "zsh", now)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || first.BackupPath == "" {
		t.Fatalf("resultado = %+v", first)
	}
	backup, err := os.ReadFile(first.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != "alias ll='ls -l'\n" {
		t.Fatalf("el respaldo no conserva el original: %q", backup)
	}
	data, _ := os.ReadFile(rc)
	if !strings.Contains(string(data), "alias ll='ls -l'") {
		t.Fatal("se perdió el contenido original")
	}
	if strings.Count(string(data), ProfileMarkerStart) != 1 {
		t.Fatalf("bloque duplicado o ausente:\n%s", data)
	}

	second, err := EnsureProfilePATH(home, "zsh", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed {
		t.Fatal("una segunda ejecución volvió a editar el perfil")
	}
	data2, _ := os.ReadFile(rc)
	if strings.Count(string(data2), ProfileMarkerStart) != 1 {
		t.Fatal("se duplicó el bloque")
	}
}

func TestEnsureProfilePATHFish(t *testing.T) {
	home := t.TempDir()
	if _, err := EnsureProfilePATH(home, "fish", time.Now()); err != nil {
		t.Fatal(err)
	}
	path, _ := ProfilePath(home, "fish")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "set -gx PATH $HOME/.local/bin $PATH") {
		t.Fatalf("sintaxis fish ausente:\n%s", data)
	}
}

func TestEnsureProfilePATHBashPrefersExistingProfile(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".bash_profile")
	if err := os.WriteFile(profile, []byte("# profile\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := EnsureProfilePATH(home, "bash", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.File != profile {
		t.Fatalf("archivo = %q, want %q", res.File, profile)
	}
}

func TestShellUnsupported(t *testing.T) {
	t.Setenv("SHELL", "/bin/tcsh")
	if _, err := ShellFromEnv(); !errors.Is(err, ErrUnsupportedShell) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsureUserLink(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, "engines")
	target := filepath.Join(owned, "trivy", "0.76.1", "trivy")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "bin", "trivy")

	changed, err := EnsureUserLink(link, target, owned)
	if err != nil || !changed {
		t.Fatalf("crear enlace: changed=%v err=%v", changed, err)
	}
	changed, err = EnsureUserLink(link, target, owned)
	if err != nil || changed {
		t.Fatalf("segunda vez: changed=%v err=%v", changed, err)
	}

	// Actualización hacia otra versión propia.
	target2 := filepath.Join(owned, "trivy", "0.77.0", "trivy")
	if err := os.MkdirAll(filepath.Dir(target2), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target2, []byte("y"), 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err = EnsureUserLink(link, target2, owned)
	if err != nil || !changed {
		t.Fatalf("actualizar enlace: changed=%v err=%v", changed, err)
	}
	if got, _ := os.Readlink(link); got != target2 {
		t.Fatalf("enlace = %q", got)
	}
}

func TestEnsureUserLinkRefusesForeign(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "bin", "trivy")
	if err := os.MkdirAll(filepath.Dir(foreign), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureUserLink(foreign, filepath.Join(dir, "otro"), filepath.Join(dir, "engines")); !errors.Is(err, ErrForeignBinary) {
		t.Fatalf("err = %v", err)
	}

	link := filepath.Join(dir, "bin", "otro")
	other := filepath.Join(dir, "ajeno")
	if err := os.WriteFile(other, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureUserLink(link, filepath.Join(dir, "engines", "trivy"), filepath.Join(dir, "engines")); !errors.Is(err, ErrForeignBinary) {
		t.Fatalf("err = %v", err)
	}
}
