package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExclusiveLockBlocksSecond(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "cache.lock")
	first, err := Acquire(context.Background(), path, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Release() }()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, path, false, 0); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("segundo bloqueo exclusivo: err = %v, want ErrLockTimeout", err)
	}
}

func TestSharedLocksCoexist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "cache.lock")
	a, err := Acquire(context.Background(), path, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Release() }()
	b, err := Acquire(context.Background(), path, true, time.Second)
	if err != nil {
		t.Fatalf("dos bloqueos compartidos no conviven: %v", err)
	}
	defer func() { _ = b.Release() }()
}

func TestExclusiveWaitsForShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "cache.lock")
	shared, err := Acquire(context.Background(), path, true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, path, false, 0); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("exclusivo con compartido activo: err = %v", err)
	}
	_ = shared.Release()

	excl, err := Acquire(context.Background(), path, false, time.Second)
	if err != nil {
		t.Fatalf("no se pudo tomar el exclusivo tras liberar el compartido: %v", err)
	}
	_ = excl.Release()
}

func TestLockPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "cache.lock")
	l, err := Acquire(context.Background(), path, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permisos = %o, want 600", perm)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("Release no es idempotente: %v", err)
	}
}

func TestAcquireHonorsCanceledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locks", "cache.lock")
	holder, err := Acquire(context.Background(), path, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Release() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Acquire(ctx, path, false, 0); err == nil {
		t.Fatal("se tomó un bloqueo con contexto cancelado")
	}
}
