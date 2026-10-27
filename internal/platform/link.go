package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrForeignBinary indica que la ruta ya la ocupa un binario ajeno.
var ErrForeignBinary = errors.New("la ruta ya está ocupada por una instalación ajena")

// EnsureUserLink crea o actualiza un enlace simbólico hacia target, sin pisar
// instalaciones ajenas (ADR-11). Devuelve true si cambió el enlace.
func EnsureUserLink(linkPath, target string, ownedRoots ...string) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil { //nolint:gosec // ~/.local/bin es un directorio público del usuario
		return false, err
	}
	info, err := os.Lstat(linkPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Symlink(target, linkPath); err != nil {
			return false, fmt.Errorf("crear enlace %s: %w", linkPath, err)
		}
		return true, nil
	case err != nil:
		return false, err
	}

	if info.Mode()&os.ModeSymlink == 0 {
		return false, fmt.Errorf("%s: %w", linkPath, ErrForeignBinary)
	}
	current, err := os.Readlink(linkPath)
	if err != nil {
		return false, err
	}
	if current == target {
		return false, nil
	}
	owned := false
	for _, root := range ownedRoots {
		if root != "" && strings.HasPrefix(current, root+string(filepath.Separator)) {
			owned = true
			break
		}
	}
	if !owned {
		return false, fmt.Errorf("%s apunta a %s: %w", linkPath, current, ErrForeignBinary)
	}

	tmp := linkPath + ".tmp-cgc-scan"
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("actualizar enlace %s: %w", linkPath, err)
	}
	return true, nil
}

// UserBinDir devuelve el directorio de ejecutables del usuario.
func UserBinDir(home string) string { return filepath.Join(home, ".local", "bin") }
