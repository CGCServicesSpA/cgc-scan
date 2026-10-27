package provision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// EnsureDockerImage comprueba que la imagen fijada por digest está presente y,
// si se permite, la descarga. Nunca resuelve un tag mutable.
func EnsureDockerImage(ctx context.Context, dockerBin, image string, allowPull bool) (bool, error) {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	if !strings.Contains(image, "@sha256:") {
		return false, fmt.Errorf("la imagen %q no está fijada por digest", image)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := exec.CommandContext(cctx, dockerBin, "image", "inspect", "--format", "{{.Id}}", image).Run(); err == nil { //nolint:gosec // dockerBin es configuración del runner
		return false, nil
	}
	if !allowPull {
		return false, fmt.Errorf("la imagen %s no está descargada y la instalación automática está deshabilitada", image)
	}
	pctx, cancelPull := context.WithTimeout(ctx, 20*time.Minute)
	defer cancelPull()
	cmd := exec.CommandContext(pctx, dockerBin, "pull", image) //nolint:gosec // dockerBin es configuración del runner
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("descargar la imagen %s: %w", image, err)
	}
	return true, nil
}

// EnsureVolume crea el volumen nombrado si no existe y lo devuelve.
func EnsureVolume(ctx context.Context, dockerBin, name string) (bool, error) {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	if name == "" {
		return false, errors.New("volumen vacío")
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := exec.CommandContext(cctx, dockerBin, "volume", "inspect", name).Run(); err == nil { //nolint:gosec // dockerBin es configuración del runner
		return false, nil
	}
	cctx2, cancel2 := context.WithTimeout(ctx, 30*time.Second)
	defer cancel2()
	if out, err := exec.CommandContext(cctx2, dockerBin, "volume", "create", name).CombinedOutput(); err != nil { //nolint:gosec // dockerBin es configuración del runner
		return false, fmt.Errorf("crear volumen %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// DockerDBMetadata lee los metadatos de la base dentro del volumen, sin montar
// el proyecto y sin red.
func DockerDBMetadata(ctx context.Context, r *runner.Docker) (DBInfo, error) {
	inv := runner.Invocation{
		Engine:     "trivy",
		Entrypoint: "/bin/sh",
		Args:       []string{"-c", "cat /cache/db/metadata.json"},
		Timeout:    30 * time.Second,
		MaxOutput:  64 << 10,
	}
	res, err := r.Run(ctx, inv)
	if err != nil {
		return DBInfo{}, fmt.Errorf("leer metadatos de la base en el contenedor: %w", err)
	}
	if res.ExitCode != 0 {
		if strings.Contains(string(res.Stderr), "No such file") {
			return DBInfo{}, ErrDBAbsent
		}
		return DBInfo{}, fmt.Errorf("leer metadatos de la base: %s", strings.TrimSpace(string(res.Stderr)))
	}
	return parseDBMetadata(res.Stdout)
}

// UpdateDBDocker ejecuta el contenedor actualizador: con red y el volumen de
// caché, sin el proyecto montado (PRD §6.4).
func UpdateDBDocker(ctx context.Context, r *runner.Docker, timeout time.Duration) (DBInfo, error) {
	inv := runner.Invocation{
		Engine: "trivy",
		Args: []string{
			"fs", "--download-db-only",
			"--cache-dir", "/cache",
			"--disable-telemetry", "--skip-version-check", "--no-progress",
		},
		AllowNetwork: true,
		Timeout:      timeout,
		MaxOutput:    1 << 20,
	}
	res, err := r.Run(ctx, inv)
	if err != nil {
		return DBInfo{}, fmt.Errorf("actualizar la base en el contenedor: %w", err)
	}
	if res.ExitCode != 0 {
		return DBInfo{}, fmt.Errorf("actualizar la base en el contenedor: código %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	info, err := DockerDBMetadata(ctx, r)
	if err != nil {
		return DBInfo{}, err
	}
	info.Status = "updated"
	return info, nil
}

// UpdateChecks descarga el bundle de checks de Trivy con un escaneo de
// configuración sobre un directorio vacío. Es la única operación equivalente
// que expone la versión fijada del motor.
func UpdateChecks(ctx context.Context, r runner.Runner, binary, cacheDir string, timeout time.Duration) error {
	args := []string{
		"fs", "--scanners", "misconfig",
		"--skip-db-update", "--skip-java-db-update", "--offline-scan",
		"--disable-telemetry", "--skip-version-check", "--no-progress",
		"--cache-dir", cacheDir,
	}
	inv := runner.Invocation{
		Engine:       "trivy",
		Binary:       binary,
		Args:         args,
		AllowNetwork: true,
		Timeout:      timeout,
		MaxOutput:    1 << 20,
	}
	switch r.Kind() {
	case "docker":
		// El tmpfs /tmp está vacío y no contiene el proyecto.
		inv.Args = append(inv.Args, "/tmp")
	case "global":
		dir, err := os.MkdirTemp("", "cgc-checks-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(dir) }()
		inv.Dir = dir
		inv.Args = append(inv.Args, ".")
		inv.Env = map[string]string{"TRIVY_SKIP_VERSION_CHECK": "true"}
	default:
		return fmt.Errorf("runner %q no soportado para actualizar checks", r.Kind())
	}
	res, err := r.Run(ctx, inv)
	if err != nil {
		return fmt.Errorf("actualizar checks: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("actualizar checks: código %d: %s", res.ExitCode, lastLine(res.Stderr))
	}
	return nil
}
