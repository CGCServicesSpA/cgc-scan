package runner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

func testGlobal(t *testing.T) *Global {
	t.Helper()
	base := t.TempDir()
	return &Global{Paths: platform.Paths{
		ConfigDir: filepath.Join(base, "config"),
		DataDir:   filepath.Join(base, "data"),
		CacheDir:  filepath.Join(base, "cache"),
	}}
}

func TestRunCapturesStreamsAndExitCode(t *testing.T) {
	g := testGlobal(t)
	inv := Invocation{
		Engine:  "trivy",
		Binary:  "/bin/sh",
		Args:    []string{"-c", "echo salida; echo error >&2; exit 7"},
		Timeout: 5 * time.Second,
	}
	res, err := g.Run(context.Background(), inv)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("exit = %d, want 7", res.ExitCode)
	}
	if string(res.Stdout) != "salida\n" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if string(res.Stderr) != "error\n" {
		t.Errorf("stderr = %q", res.Stderr)
	}
	if res.TimedOut || res.Canceled || res.Truncated {
		t.Errorf("estado inesperado: %+v", res)
	}
}

func TestRunUsesIsolatedEnvironment(t *testing.T) {
	g := testGlobal(t)
	t.Setenv("SECRET_TOKEN", "no-debe-pasarse")
	res, err := g.Run(context.Background(), Invocation{
		Engine: "trivy",
		Binary: "/bin/sh",
		Args:   []string{"-c", "env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout)
	if strings.Contains(out, "SECRET_TOKEN") || strings.Contains(out, "no-debe-pasarse") {
		t.Fatalf("el entorno filtró una variable del padre:\n%s", out)
	}
	home := g.Paths.SandboxHome("trivy")
	for _, want := range []string{
		"HOME=" + home,
		"TMPDIR=" + filepath.Join(home, "tmp"),
		"HTTPS_PROXY=" + invalidProxy,
		"HTTP_PROXY=" + invalidProxy,
		"NO_PROXY=",
		"TZ=UTC",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en el entorno:\n%s", want, out)
		}
	}
	if strings.Contains(out, "GOPATH") || strings.Contains(out, "DOCKER_HOST") {
		t.Errorf("el entorno incluye variables no permitidas:\n%s", out)
	}
}

func TestRunRejectsDisallowedEnvKey(t *testing.T) {
	g := testGlobal(t)
	_, err := g.Run(context.Background(), Invocation{
		Engine: "trivy", Binary: "/bin/sh", Args: []string{"-c", "true"},
		Env: map[string]string{"LD_PRELOAD": "/tmp/x.so"},
	})
	if err == nil {
		t.Fatal("se aceptó una variable no permitida")
	}
}

func TestRunAllowsAdapterEnv(t *testing.T) {
	g := testGlobal(t)
	res, err := g.Run(context.Background(), Invocation{
		Engine: "trivy", Binary: "/bin/sh", Args: []string{"-c", "echo $TRIVY_SKIP_VERSION_CHECK"},
		Env: map[string]string{"TRIVY_SKIP_VERSION_CHECK": "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(res.Stdout)) != "true" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestRunRequiresAbsoluteBinary(t *testing.T) {
	g := testGlobal(t)
	if _, err := g.Run(context.Background(), Invocation{Engine: "trivy", Binary: "sh"}); err == nil {
		t.Fatal("se aceptó un binario relativo")
	}
}

func TestRunTimesOutAndKillsGroup(t *testing.T) {
	g := testGlobal(t)
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	script := "sleep 30 & echo $! > " + pidFile + "; wait"
	start := time.Now()
	res, err := g.Run(context.Background(), Invocation{
		Engine: "trivy", Binary: "/bin/sh", Args: []string{"-c", script},
		Timeout: 400 * time.Millisecond,
	})
	if err == nil && !res.TimedOut {
		t.Fatal("se esperaba timeout")
	}
	if !res.TimedOut {
		t.Errorf("TimedOut = false, resultado %+v", res)
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Errorf("el timeout tardó %v", elapsed)
	}
	waitForNoProcess(t, pidFile)
}

func TestRunCanceled(t *testing.T) {
	g := testGlobal(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	res, err := g.Run(ctx, Invocation{
		Engine: "trivy", Binary: "/bin/sh", Args: []string{"-c", "sleep 30"},
		Timeout: 10 * time.Second,
	})
	if err == nil && !res.Canceled {
		t.Fatal("se esperaba cancelación")
	}
	if !res.Canceled {
		t.Errorf("Canceled = false: %+v", res)
	}
}

func TestRunTruncatesOutput(t *testing.T) {
	g := testGlobal(t)
	g.MaxOutput = 1024
	res, err := g.Run(context.Background(), Invocation{
		Engine: "trivy", Binary: "/bin/sh",
		Args:    []string{"-c", "yes a | head -c 200000"},
		Timeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("se esperaba error por tope de salida")
	}
	if !res.Truncated {
		t.Errorf("Truncated = false: %+v", res)
	}
	if int64(len(res.Stdout)) > 1024 {
		t.Errorf("stdout de %d bytes supera el tope", len(res.Stdout))
	}
}

func TestRunWorkDir(t *testing.T) {
	g := testGlobal(t)
	dir := t.TempDir()
	res, err := g.Run(context.Background(), Invocation{
		Engine: "trivy", Binary: "/bin/sh", Args: []string{"-c", "pwd"}, Dir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(string(res.Stdout)))
	want, _ := filepath.EvalSymlinks(dir)
	if got != want {
		t.Errorf("pwd = %q, want %q", got, want)
	}
}

func TestIsolationIsConfigured(t *testing.T) {
	g := testGlobal(t)
	lvl, err := g.Isolation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if lvl != IsolationConfigured {
		t.Fatalf("nivel = %q", lvl)
	}
}

func waitForNoProcess(t *testing.T, pidFile string) {
	t.Helper()
	var data []byte
	var err error
	for i := 0; i < 50; i++ {
		data, err = os.ReadFile(pidFile)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("no se escribió el pid del hijo: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("pid inválido: %v", err)
	}
	for i := 0; i < 60; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		// En Linux, un proceso muerto pero no recolectado por PID 1 sigue
		// respondiendo a la señal 0; su estado en /proc es Z.
		if stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")); err == nil {
			fields := strings.Fields(string(stat))
			if len(fields) > 2 && fields[2] == "Z" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("el proceso hijo %d sigue vivo tras el timeout", pid)
}
