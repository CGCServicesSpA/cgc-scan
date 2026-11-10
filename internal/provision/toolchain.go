package provision

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/toolchain"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// ToolchainImage es el resultado de aprovisionar la imagen de un adaptador
// sobre la versión del lenguaje que declara el proyecto.
type ToolchainImage struct {
	Tag string
	// Base es la imagen oficial usada como base (sin digest).
	Base string
	// Digest es el digest resuelto de la base, p. ej. sha256:abc.
	Digest string
	// Built indica que la imagen se construyó en esta ejecución.
	Built bool
	// Cached indica que se reutilizó una imagen local ya construida.
	Cached bool
}

// ToolchainOptions configura la construcción de imágenes por lenguaje.
type ToolchainOptions struct {
	DockerBin     string
	Offline       bool
	NoAutoInstall bool
	// Arch es la arquitectura del daemon (amd64, arm64 o su alias).
	Arch         string
	HTTPClient   *http.Client
	MaxDownload  int64
	BuildTimeout time.Duration
}

// EnsureToolchainImage construye (o reutiliza) la imagen derivada de un
// adaptador sobre la imagen oficial del lenguaje y la versión detectada en el
// proyecto. La base se fija por el digest que se resuelve en el momento; esa
// resolución se registra en el reporte porque no está en el manifiesto.
func EnsureToolchainImage(ctx context.Context, opts ToolchainOptions, spec toolchain.Spec, adapter manifest.Adapter) (ToolchainImage, error) {
	if spec.Family() == "" {
		return ToolchainImage{}, fmt.Errorf("toolchain: la unidad no declara un lenguaje soportado")
	}
	if opts.DockerBin == "" {
		opts.DockerBin = "docker"
	}
	if spec.Version != "" && !versionish(spec.Version) {
		return ToolchainImage{}, fmt.Errorf("toolchain: versión inválida %q", spec.Version)
	}
	arch := opts.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	plan, err := NewToolchainPlan(spec, adapter, arch)
	if err != nil {
		return ToolchainImage{}, err
	}

	tag := plan.Tag
	if info, err := inspectImage(ctx, opts.DockerBin, tag); err == nil {
		info.Tag = tag
		info.Cached = true
		return info, nil
	}
	if opts.Offline || opts.NoAutoInstall {
		reason := "--no-auto-install"
		if opts.Offline {
			reason = "--offline"
		}
		return ToolchainImage{}, fmt.Errorf("la imagen %s no está construida y %s prohíbe construirla", tag, reason)
	}

	base, digest, err := resolveBase(ctx, opts, plan.BaseCandidates)
	if err != nil {
		return ToolchainImage{}, err
	}
	dir, err := os.MkdirTemp("", "cgc-toolchain-*")
	if err != nil {
		return ToolchainImage{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := writeBuildContext(ctx, opts, dir, plan); err != nil {
		return ToolchainImage{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), plan.Render(base+"@"+digest), 0o600); err != nil {
		return ToolchainImage{}, err
	}

	timeout := opts.BuildTimeout
	if timeout <= 0 {
		timeout = 25 * time.Minute
	}
	bctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	args := []string{
		"build", "--network=default",
		"--label", "cgc-scan.base=" + base,
		"--label", "cgc-scan.base-digest=" + digest,
		"-t", tag, dir,
	}
	// #nosec G204 -- dockerBin es configuración del runner y los argumentos se
	// construyen aquí, sin shell.
	cmd := exec.CommandContext(bctx, opts.DockerBin, args...) //nolint:gosec // dockerBin es configuración del runner
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return ToolchainImage{}, fmt.Errorf("construir la imagen %s sobre %s: %w", tag, base, err)
	}
	out, err := inspectImage(ctx, opts.DockerBin, tag)
	if err != nil {
		return ToolchainImage{}, fmt.Errorf("la imagen %s no quedó disponible: %w", tag, err)
	}
	out.Tag = tag
	out.Base = base
	out.Digest = digest
	out.Built = true
	return out, nil
}

// NewToolchainPlan expone la generación del plan para pruebas.
func NewToolchainPlan(spec toolchain.Spec, adapter manifest.Adapter, arch string) (toolchain.Plan, error) {
	return toolchain.NewPlan(spec, adapter, arch)
}

func inspectImage(ctx context.Context, dockerBin, ref string) (ToolchainImage, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, dockerBin, "image", "inspect", //nolint:gosec // dockerBin es configuración del runner
		"--format", "{{.Id}}|{{index .Config.Labels \"cgc-scan.base\"}}|{{index .Config.Labels \"cgc-scan.base-digest\"}}", ref).Output()
	if err != nil {
		return ToolchainImage{}, err
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 3)
	info := ToolchainImage{}
	if len(parts) >= 2 {
		info.Base = parts[1]
	}
	if len(parts) == 3 {
		info.Digest = parts[2]
	}
	return info, nil
}

func resolveBase(ctx context.Context, opts ToolchainOptions, candidates []string) (string, string, error) {
	if len(candidates) == 0 {
		return "", "", errors.New("toolchain: no hay imágenes base candidatas")
	}
	var lastErr error
	for _, candidate := range candidates {
		digest, err := ensureBase(ctx, opts, candidate)
		if err == nil {
			return candidate, digest, nil
		}
		lastErr = err
	}
	return "", "", fmt.Errorf("no se pudo preparar ninguna imagen base compatible (%s): %w",
		strings.Join(candidates, ", "), lastErr)
}

// ensureBase descarga la imagen si hace falta y devuelve su digest.
func ensureBase(ctx context.Context, opts ToolchainOptions, image string) (string, error) {
	if digest, err := baseDigest(ctx, opts.DockerBin, image); err == nil && digest != "" {
		return digest, nil
	}
	if opts.Offline || opts.NoAutoInstall {
		return "", fmt.Errorf("la imagen base %s no está descargada", image)
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	// #nosec G204 -- dockerBin es configuración del runner.
	cmd := exec.CommandContext(pctx, opts.DockerBin, "pull", image) //nolint:gosec // dockerBin es configuración del runner
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("descargar la imagen base %s: %w", image, err)
	}
	digest, err := baseDigest(ctx, opts.DockerBin, image)
	if err != nil || digest == "" {
		return "", fmt.Errorf("no se pudo resolver el digest de %s: %w", image, err)
	}
	return digest, nil
}

func baseDigest(ctx context.Context, dockerBin, image string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, dockerBin, "image", "inspect", //nolint:gosec // dockerBin es configuración del runner
		"--format", `{{index .RepoDigests 0}}|{{.Id}}`, image).Output()
	if err != nil {
		return "", err
	}
	parts := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	if len(parts) == 2 {
		if i := strings.Index(parts[0], "sha256:"); i >= 0 {
			return parts[0][i:], nil
		}
		if strings.HasPrefix(parts[1], "sha256:") {
			return parts[1], nil
		}
	}
	return "", errors.New("la imagen no expone digest")
}

func writeBuildContext(ctx context.Context, opts ToolchainOptions, dir string, plan toolchain.Plan) error {
	for name, data := range plan.Files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	max := opts.MaxDownload
	if max <= 0 {
		max = DefaultMaxDownload
	}
	for _, art := range plan.Artifacts {
		tmp, err := os.CreateTemp(dir, ".artifact-*")
		if err != nil {
			return err
		}
		tmpPath := tmp.Name()
		if _, err := downloadVerified(ctx, client, art.URL, art.SHA256, max, tmp); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		final := filepath.Join(dir, art.Name)
		if art.ExtractBinary != "" {
			out, err := os.OpenFile(final, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755) //nolint:gosec // el binario debe ser ejecutable
			if err != nil {
				return err
			}
			if err := extractBinary(tmpPath, art.ExtractBinary, out); err != nil {
				_ = out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		} else if err := os.Rename(tmpPath, final); err != nil {
			return err
		}
		if art.ExtractBinary == "" {
			if err := os.Chmod(final, 0o755); err != nil { //nolint:gosec // el artefacto debe ser ejecutable
				return err
			}
		}
		_ = os.Remove(tmpPath)
	}
	return nil
}

// versionish comprueba que una versión solo contiene dígitos y puntos, sin
// componentes vacíos, para no inyectar texto del proyecto en referencias de
// imagen.
func versionish(v string) bool {
	if v == "" {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}
