package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Docker ejecuta motores dentro de un contenedor sin red, con el sistema de
// archivos de solo lectura, sin capacidades y con el proyecto montado en
// solo lectura (design §6.1, ADR-09).
type Docker struct {
	// Image es la referencia fijada por digest, p. ej. ghcr.io/...@sha256:...
	Image string
	// Volume es el volumen nombrado de caché, propio del usuario.
	Volume string
	// DockerBin es el binario del CLI de Docker (por defecto "docker").
	DockerBin string
	MaxOutput int64
	MaxStderr int64
}

// Kind identifica el runner en el reporte.
func (d *Docker) Kind() string { return "docker" }

// Isolation declara el nivel fuerte: el sistema impide la salida de red.
func (d *Docker) Isolation(context.Context) (IsolationLevel, error) {
	return IsolationEnforced, nil
}

// Run ejecuta una invocación en un contenedor efímero. El contenedor
// actualizador (AllowNetwork) no monta el proyecto; el escáner no tiene red.
func (d *Docker) Run(ctx context.Context, inv Invocation) (Result, error) {
	if d.Image == "" || !strings.Contains(d.Image, "@sha256:") {
		return Result{}, errors.New("runner docker: falta la imagen fijada por digest")
	}
	if d.Volume == "" {
		return Result{}, errors.New("runner docker: falta el volumen de caché")
	}
	if inv.MaxOutput == 0 {
		inv.MaxOutput = d.maxOutput()
	}
	timeout := inv.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	args, err := d.buildArgs(inv)
	if err != nil {
		return Result{}, err
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	bin := d.DockerBin
	if bin == "" {
		bin = "docker"
	}
	// #nosec G204 -- el binario es docker y los argumentos se construyen aquí,
	// sin pasar por un shell.
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Env = dockerEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout := &cappedBuffer{limit: inv.MaxOutput, onExceed: cancel}
	stderr := &cappedBuffer{limit: d.maxStderr()}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = 5 * time.Second

	start := time.Now()
	waitErr := cmd.Run()
	res := Result{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Duration:  time.Since(start),
		Truncated: stdout.Truncated() || stderr.Truncated(),
		Canceled:  ctx.Err() != nil,
		TimedOut:  errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil,
	}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		res.ExitCode = -1
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return res, fmt.Errorf("ejecutar docker: %w", waitErr)
		}
	}
	if res.Truncated {
		return res, fmt.Errorf("la salida de %s superó el tope de %d bytes", inv.Engine, inv.MaxOutput)
	}
	return res, nil
}

func (d *Docker) buildArgs(inv Invocation) ([]string, error) {
	args := []string{"run", "--rm"}
	if !inv.AllowNetwork {
		args = append(args, "--network", "none")
	}
	args = append(args,
		"--read-only", "--tmpfs", "/tmp",
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "512", "--memory", "2g",
	)
	if inv.Entrypoint != "" {
		args = append(args, "--entrypoint", inv.Entrypoint)
	}
	if inv.ProjectRO != "" {
		root, err := filepath.Abs(inv.ProjectRO)
		if err != nil {
			return nil, err
		}
		args = append(args, "-v", root+":/src:ro")
		work := "/src"
		if inv.Dir != "" {
			abs, err := filepath.Abs(inv.Dir)
			if err != nil {
				return nil, err
			}
			rel, err := filepath.Rel(root, abs)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return nil, fmt.Errorf("el directorio %s está fuera del proyecto %s", inv.Dir, root)
			}
			if rel != "." {
				work = "/src/" + filepath.ToSlash(rel)
			}
		}
		args = append(args, "-w", work)
	}
	args = append(args, "-v", d.Volume+":/cache", d.Image)
	return append(args, inv.Args...), nil
}

func (d *Docker) maxOutput() int64 {
	if d.MaxOutput > 0 {
		return d.MaxOutput
	}
	return DefaultMaxOutput
}

func (d *Docker) maxStderr() int64 {
	if d.MaxStderr > 0 {
		return d.MaxStderr
	}
	return DefaultMaxStderr
}

// dockerEnv entrega al CLI de Docker solo lo necesario para hablar con el
// daemon; no se pasa el entorno del usuario a los contenedores.
func dockerEnv() []string {
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"LANG=C.UTF-8",
	}
	for _, k := range []string{"HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// VolumeName devuelve el volumen propio del usuario, que evita compartir
// caché entre personas que usan el mismo daemon (PRD §6.4).
func VolumeName(uid int) string {
	return "cgc-scan-trivy-cache-" + strconv.Itoa(uid)
}
