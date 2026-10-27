package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// ErrLockTimeout se devuelve cuando no se pudo tomar el bloqueo a tiempo.
var ErrLockTimeout = errors.New("tiempo de espera agotado al tomar el bloqueo")

// Lock es un bloqueo de archivo exclusivo o compartido. Se usa para serializar
// la provisión de motores y las actualizaciones de bases (design §7.4).
type Lock struct {
	f    *flock.Flock
	path string
}

// Acquire toma un bloqueo sobre path. Si shared es verdadero, el bloqueo es
// compartido (varios lectores); si no, exclusivo. Espera hasta que el contexto
// termine o se agote timeout (0 = sin límite explícito, solo contexto).
func Acquire(ctx context.Context, path string, shared bool, timeout time.Duration) (*Lock, error) {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	// Se crea con permisos privados antes de que flock lo abra.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("crear bloqueo %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := EnsureFileMode(path, 0o600); err != nil {
		return nil, err
	}

	fl := flock.New(path)
	waitCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		waitCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	var ok bool
	if shared {
		ok, err = fl.TryRLockContext(waitCtx, 100*time.Millisecond)
	} else {
		ok, err = fl.TryLockContext(waitCtx, 100*time.Millisecond)
	}
	if err != nil {
		_ = fl.Close()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s: %w", path, ErrLockTimeout)
		}
		return nil, fmt.Errorf("tomar bloqueo %s: %w", path, err)
	}
	if !ok {
		_ = fl.Close()
		return nil, fmt.Errorf("%s: %w", path, ErrLockTimeout)
	}
	return &Lock{f: fl, path: path}, nil
}

// Release libera el bloqueo. Es idempotente.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	unlockErr := l.f.Unlock()
	closeErr := l.f.Close()
	l.f = nil
	if unlockErr != nil {
		return fmt.Errorf("liberar bloqueo %s: %w", l.path, unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("cerrar bloqueo %s: %w", l.path, closeErr)
	}
	return nil
}
