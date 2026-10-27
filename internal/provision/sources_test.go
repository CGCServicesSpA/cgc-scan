package provision

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

type captureRunner struct {
	calls []runner.Invocation
}

func (c *captureRunner) Kind() string { return "global" }
func (c *captureRunner) Isolation(context.Context) (runner.IsolationLevel, error) {
	return runner.IsolationConfigured, nil
}
func (c *captureRunner) Run(_ context.Context, inv runner.Invocation) (runner.Result, error) {
	c.calls = append(c.calls, inv)
	return runner.Result{ExitCode: 0}, nil
}

type captureDocker struct {
	captureRunner
}

func (c *captureDocker) Kind() string { return "docker" }

func TestJavaDBSourceArgs(t *testing.T) {
	r := &captureRunner{}
	src := &TrivySource{Kind: "trivy-java-db", Runner: r, CacheDir: "/cache", Timeout: time.Second}
	if _, err := src.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("llamadas = %d", len(r.calls))
	}
	inv := r.calls[0]
	joined := strings.Join(inv.Args, " ")
	for _, want := range []string{"--download-java-db-only", "--cache-dir /cache"} {
		if !strings.Contains(joined, want) {
			t.Errorf("faltan %q en %v", want, inv.Args)
		}
	}
	if !inv.AllowNetwork {
		t.Error("la actualización de preparación debe permitir red")
	}
}

func TestChecksSourceGlobalUsesEmptyDir(t *testing.T) {
	r := &captureRunner{}
	src := &TrivySource{Kind: "trivy-checks", Runner: r, CacheDir: "/cache", Timeout: time.Second}
	if _, err := src.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 {
		t.Fatalf("llamadas = %d", len(r.calls))
	}
	inv := r.calls[0]
	joined := strings.Join(inv.Args, " ")
	if !strings.Contains(joined, "--scanners misconfig") {
		t.Errorf("args = %v", inv.Args)
	}
	if !strings.Contains(joined, "--skip-db-update") {
		t.Error("la actualización de checks no debe actualizar la base")
	}
	if inv.Dir == "" || !strings.HasSuffix(inv.Args[len(inv.Args)-1], ".") {
		t.Errorf("no se usó un directorio vacío: dir=%q args=%v", inv.Dir, inv.Args)
	}
	if _, err := os.Stat(inv.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("el directorio temporal no se limpió: %v", err)
	}
}

func TestChecksSourceDockerTargetsTmp(t *testing.T) {
	r := &captureDocker{}
	src := &TrivySource{Kind: "trivy-checks", Runner: r, Docker: &runner.Docker{}, CacheDir: "/cache", Timeout: time.Second}
	if _, err := src.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.calls[0].Args[len(r.calls[0].Args)-1]; got != "/tmp" {
		t.Fatalf("objetivo = %q, want /tmp", got)
	}
	if r.calls[0].ProjectRO != "" {
		t.Error("el contenedor de checks no debe montar el proyecto")
	}
}

func TestDBSourceStateMissing(t *testing.T) {
	src := &TrivySource{Kind: "trivy-db", Runner: &captureRunner{}, CacheDir: t.TempDir()}
	if _, err := src.State(context.Background()); !errors.Is(err, ErrDBAbsent) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownSource(t *testing.T) {
	src := &TrivySource{Kind: "magia", Runner: &captureRunner{}}
	if _, err := src.Update(context.Background()); err == nil {
		t.Fatal("se aceptó una fuente desconocida")
	}
}

type failingRunner struct{ captureRunner }

func (f *failingRunner) Run(context.Context, runner.Invocation) (runner.Result, error) {
	return runner.Result{ExitCode: 1, Stderr: []byte("sin red\n")}, nil
}

func TestUpdateFailureIsReported(t *testing.T) {
	src := &TrivySource{Kind: "trivy-db", Runner: &failingRunner{}, CacheDir: t.TempDir(), Timeout: time.Second}
	info, err := src.Update(context.Background())
	if err == nil {
		t.Fatal("un fallo del actualizador debe devolver error")
	}
	if info.Status == "updated" {
		t.Fatalf("se declaró la base actualizada pese al fallo: %+v", info)
	}
	if !strings.Contains(err.Error(), "sin red") {
		t.Errorf("el error no incluye el detalle del motor: %v", err)
	}
}
