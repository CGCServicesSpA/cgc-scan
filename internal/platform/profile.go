package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Marcadores del bloque gestionado en el perfil de shell.
const (
	ProfileMarkerStart = "# >>> cgc-scan (no editar este bloque) >>>"
	ProfileMarkerEnd   = "# <<< cgc-scan <<<"
)

// ErrUnsupportedShell indica un intérprete no soportado.
var ErrUnsupportedShell = errors.New("intérprete de shell no soportado")

// ShellFromEnv detecta el shell por $SHELL.
func ShellFromEnv() (string, error) {
	sh := filepath.Base(strings.TrimSpace(os.Getenv("SHELL")))
	switch sh {
	case "zsh", "bash", "fish":
		return sh, nil
	case "":
		return "bash", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedShell, sh)
	}
}

// ProfilePath devuelve el archivo de perfil adecuado para el shell.
func ProfilePath(home, shell string) (string, error) {
	switch shell {
	case "zsh":
		return filepath.Join(home, ".zshrc"), nil
	case "bash":
		rc := filepath.Join(home, ".bashrc")
		if _, err := os.Stat(rc); err == nil {
			return rc, nil
		}
		profile := filepath.Join(home, ".bash_profile")
		if _, err := os.Stat(profile); err == nil {
			return profile, nil
		}
		return rc, nil
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedShell, shell)
	}
}

// ProfileResult describe el resultado de asegurar el bloque.
type ProfileResult struct {
	File       string
	Changed    bool
	BackupPath string
}

// EnsureProfilePATH agrega el bloque de PATH de forma idempotente, con copia
// de respaldo del perfil original. Nunca duplica el bloque (CA-37).
func EnsureProfilePATH(home, shell string, now time.Time) (ProfileResult, error) {
	path, err := ProfilePath(home, shell)
	if err != nil {
		return ProfileResult{}, err
	}
	res := ProfileResult{File: path}

	original, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, fmt.Errorf("leer perfil %s: %w", path, err)
	}
	if strings.Contains(string(original), ProfileMarkerStart) {
		return res, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return res, fmt.Errorf("crear directorio del perfil: %w", err)
	}
	if len(original) > 0 {
		backup := fmt.Sprintf("%s.cgc-scan.bak-%s", path, now.UTC().Format("20060102T150405Z"))
		if err := os.WriteFile(backup, original, 0o600); err != nil { //nolint:gosec // ruta derivada de $HOME y del shell del usuario
			return res, fmt.Errorf("crear respaldo del perfil: %w", err)
		}
		res.BackupPath = backup
	}

	block := profileBlock(shell)
	var out []byte
	out = append(out, original...)
	if len(original) > 0 && original[len(original)-1] != '\n' {
		out = append(out, '\n')
	}
	if len(original) > 0 {
		out = append(out, '\n')
	}
	out = append(out, block...)

	perm := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		perm = info.Mode().Perm()
	}
	if err := WriteFileAtomic(path, out, perm); err != nil {
		return res, fmt.Errorf("editar perfil %s: %w", path, err)
	}
	res.Changed = true
	return res, nil
}

func profileBlock(shell string) string {
	if shell == "fish" {
		return ProfileMarkerStart + "\n" +
			"set -gx PATH $HOME/.local/bin $PATH\n" +
			ProfileMarkerEnd + "\n"
	}
	return ProfileMarkerStart + "\n" +
		"export PATH=\"$HOME/.local/bin:$PATH\"\n" +
		ProfileMarkerEnd + "\n"
}
