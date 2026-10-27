package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// runUpdateDB actualiza las bases sin leer ningún proyecto (PRD §6.4).
func (a *App) runUpdateDB(cmd *cobra.Command) error {
	if err := a.Paths.EnsureDirs(); err != nil {
		return IncompleteErrorf("preparar directorios: %v", err)
	}
	ms, err := manifest.Load()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	engine, err := ms.Engine("trivy")
	if err != nil {
		return IncompleteErrorf("%v", err)
	}

	info, dockerErr := runner.DetectDocker(cmd.Context())
	sel, err := runner.Resolve(runner.ResolveRequest{DockerOK: dockerErr == nil, DockerErr: dockerErr})
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	if info.Version != "" {
		slog.Info("Docker detectado", "version", info.Version, "arch", info.Arch, "context", info.Context)
	}

	var (
		r        runner.Runner
		dockerR  *runner.Docker
		binary   string
		cacheDir string
		volume   string
		image    string
	)
	switch sel.Mode {
	case "docker":
		image = engine.Image
		volume = runner.VolumeName(os.Getuid())
		if _, err := provision.EnsureDockerImage(cmd.Context(), "docker", image, true); err != nil {
			return IncompleteErrorf("%v", err)
		}
		if _, err := provision.EnsureVolume(cmd.Context(), "docker", volume); err != nil {
			return IncompleteErrorf("%v", err)
		}
		dockerR = &runner.Docker{Image: image, Volume: volume}
		r = dockerR
		cacheDir = "/cache"
	case "global":
		res, err := provision.EnsureTrivy(cmd.Context(), provision.Options{Paths: a.Paths, Manifest: ms})
		if err != nil {
			return IncompleteErrorf("%v", err)
		}
		binary = res.Path
		cacheDir = a.Paths.TrivyCacheDir()
		r = &runner.Global{Paths: a.Paths}
	default:
		return IncompleteErrorf("modalidad desconocida: %q", sel.Mode)
	}

	lock, err := platform.Acquire(cmd.Context(), filepath.Join(a.Paths.LocksDir(), "trivy-cache.lock"), false, 5*time.Minute)
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	defer func() { _ = lock.Release() }()

	sources := provision.Sources(r, dockerR, binary, cacheDir, 30*time.Minute)
	var failures []string
	for _, src := range sources {
		slog.Info("actualizando fuente", "source", src.ID())
		db, err := src.Update(cmd.Context())
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", src.ID(), err))
			slog.Error("fallo al actualizar", "source", src.ID(), "error", err)
			continue
		}
		attrs := []any{"source", src.ID(), "status", db.Status}
		if !db.UpdatedAt.IsZero() {
			attrs = append(attrs, "updated_at", db.UpdatedAt.UTC().Format(time.RFC3339))
		}
		slog.Info("fuente actualizada", attrs...)
	}
	if len(failures) > 0 {
		return IncompleteErrorf("%d fuente(s) no se pudieron actualizar: %v", len(failures), failures)
	}
	return nil
}
