package platform

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteFileAtomic escribe data en path de forma atómica: archivo temporal en el
// mismo directorio, fsync del contenido, cierre, os.Rename y fsync del
// directorio. No deja un archivo parcial si el proceso se interrumpe.
//
// perm se aplica al archivo final; el temporal se crea con 0600 y solo se
// amplía al perm solicitado si este es más permisivo.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := EnsurePrivateDir(dir); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("crear temporal para %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("aplicar permisos al temporal: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("escribir %s: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sincronizar %s: %w", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("cerrar %s: %w", path, err)
	}
	if perm != 0 && perm != 0o600 {
		if err = os.Chmod(tmpName, perm); err != nil {
			return fmt.Errorf("aplicar permisos finales a %s: %w", path, err)
		}
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publicar %s: %w", path, err)
	}
	if err = syncDir(dir); err != nil {
		return err
	}
	return nil
}

// syncDir fuerza la persistencia de la entrada de directorio tras un rename.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("abrir directorio %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sincronizar directorio %s: %w", dir, err)
	}
	return nil
}

// WritePrivateFile escribe un archivo con permisos 0600 usando escritura
// atómica. Es la forma por defecto de crear reportes y estado.
func WritePrivateFile(path string, data []byte) error {
	return WriteFileAtomic(path, data, 0o600)
}

// EnsureFileMode comprueba y, si hace falta, restringe los permisos de un
// archivo ya existente a los indicados. Nunca amplía permisos.
func EnsureFileMode(path string, perm fs.FileMode) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	if info.Mode().Perm()&^perm == 0 {
		return nil
	}
	if err := os.Chmod(path, info.Mode().Perm()&perm); err != nil {
		return fmt.Errorf("restringir permisos de %s: %w", path, err)
	}
	return nil
}

// ReadFileBounded lee un archivo rechazando los que superan limit bytes. Se
// usa para datos que provienen del proyecto o de un motor.
func ReadFileBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s supera el límite de %d bytes", path, limit)
	}
	return os.ReadFile(path)
}

// ErrEmptyPath indica una ruta vacía.
var ErrEmptyPath = errors.New("ruta vacía")
