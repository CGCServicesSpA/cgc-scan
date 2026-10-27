package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// engineSetup es el resultado de la fase de preparación: el runner elegido,
// la ruta o imagen del motor y el estado de la base.
type engineSetup struct {
	Mode           string
	Runner         runner.Runner
	Global         *runner.Global
	Docker         *runner.Docker
	Binary         string
	CacheDir       string // ruta que recibe el motor (host o /cache)
	Image          string
	Volume         string
	DB             provision.DBInfo
	Preparations   []report.Preparation
	FallbackReason string
	Shared         *platform.Lock
}

// setupEngine aplica la matriz de selección, instala o reutiliza el motor,
// prepara la caché y deja tomado el bloqueo compartido para el escaneo.
func (a *App) setupEngine(ctx context.Context, opts scanOptions, cfg config.Config, ms *manifest.Manifest, engine manifest.Engine) (*engineSetup, error) {
	required := runner.IsolationLevel(opts.RequireIsolation)
	setup := &engineSetup{Mode: opts.TrivyMode}
	if opts.TrivyMode == "global" {
		setup.Mode = "global"
	} else {
		info, dockerErr := runner.DetectDocker(ctx)
		if info.Version != "" {
			slog.Info("Docker detectado", "version", info.Version, "arch", info.Arch, "context", info.Context)
		}
		sel, err := runner.Resolve(runner.ResolveRequest{
			Explicit: opts.TrivyMode, Stored: cfg.TrivyMode, DockerOK: dockerErr == nil, DockerErr: dockerErr,
		})
		if err != nil {
			return nil, err
		}
		setup.Mode = sel.Mode
		setup.FallbackReason = sel.FallbackReason
	}

	// El aislamiento exigido se comprueba antes de descargar nada y antes de
	// leer el proyecto (CA-50).
	if required.Rank() > 0 {
		offered := runner.IsolationConfigured
		if setup.Mode == "docker" {
			offered = runner.IsolationEnforced
		}
		if required.Rank() > offered.Rank() {
			return nil, fmt.Errorf("se exigió aislamiento %s y la modalidad %s ofrece %s; el proyecto no se analizó", required, setup.Mode, offered)
		}
	}

	lockPath := filepath.Join(a.Paths.LocksDir(), "trivy-cache.lock")
	exclusive, err := platform.Acquire(ctx, lockPath, false, 5*time.Minute)
	if err != nil {
		return nil, err
	}

	allowAcquire := !opts.Offline && !opts.NoAutoInstall

	switch setup.Mode {
	case "docker":
		setup.Image = engine.Image
		setup.Volume = runner.VolumeName(os.Getuid())
		pulled, err := provision.EnsureDockerImage(ctx, "docker", engine.Image, allowAcquire)
		if err != nil {
			return nil, err
		}
		created, err := provision.EnsureVolume(ctx, "docker", setup.Volume)
		if err != nil {
			return nil, err
		}
		if pulled {
			setup.Preparations = append(setup.Preparations, report.Preparation{Action: "image", Status: "ok", Detail: "imagen descargada por digest"})
		}
		if created {
			setup.Preparations = append(setup.Preparations, report.Preparation{Action: "volume", Status: "ok", Detail: setup.Volume})
		}
		setup.Docker = &runner.Docker{Image: engine.Image, Volume: setup.Volume}
		setup.Runner = setup.Docker
		setup.CacheDir = "/cache"

		if opts.Offline {
			info, err := provision.DockerDBMetadata(ctx, setup.Docker)
			if err != nil {
				return nil, fmt.Errorf("modo offline: %w", err)
			}
			if err := provision.CheckDBAge(&info, cfg.WarnAfter(), cfg.BlockAfterOffline()); err != nil {
				return nil, err
			}
			setup.DB = info
			setup.Preparations = append(setup.Preparations, report.Preparation{Action: "db", Status: "ok", Detail: "offline: base del volumen validada"})
		} else {
			info, err := provision.UpdateDBDocker(ctx, setup.Docker, 20*time.Minute)
			if err != nil {
				return nil, err
			}
			if err := provision.UpdateChecks(ctx, setup.Docker, "", "/cache", 10*time.Minute); err != nil {
				// Un fallo de checks no invalida la base, pero la ejecución
				// queda limitada y se registra.
				setup.Preparations = append(setup.Preparations, report.Preparation{Action: "checks", Status: "failed", Detail: err.Error()})
			} else {
				setup.Preparations = append(setup.Preparations, report.Preparation{Action: "checks", Status: "ok", Detail: "bundle de checks actualizado"})
			}
			setup.DB = info
			setup.Preparations = append(setup.Preparations, report.Preparation{Action: "db", Status: "ok", Detail: "base actualizada"})
		}

	case "global":
		if opts.Offline || opts.NoAutoInstall {
			candidate := filepath.Join(a.Paths.EngineDir("trivy", engine.Version), "trivy")
			if _, statErr := os.Stat(candidate); statErr != nil {
				why := "--offline"
				if !opts.Offline {
					why = "--no-auto-install"
				}
				return nil, fmt.Errorf("no hay un Trivy %s instalado y %s prohíbe descargarlo", engine.Version, why)
			}
			setup.Binary = candidate
		} else {
			res, err := provision.EnsureTrivy(ctx, provision.Options{Paths: a.Paths, Manifest: ms})
			if err != nil {
				return nil, err
			}
			setup.Binary = res.Path
			if res.Installed {
				setup.Preparations = append(setup.Preparations, report.Preparation{Action: "engine", Status: "ok", Detail: "Trivy instalado y verificado"})
			}
		}
		setup.Global = &runner.Global{Paths: a.Paths}
		setup.Runner = setup.Global
		setup.CacheDir = cfg.CacheDir(a.Paths.TrivyCacheDir())

		if opts.Offline {
			info, err := provision.CheckDBOffline(setup.CacheDir, cfg.WarnAfter(), cfg.BlockAfterOffline())
			if err != nil {
				return nil, err
			}
			setup.DB = info
			setup.Preparations = append(setup.Preparations, report.Preparation{Action: "db", Status: "ok", Detail: "offline: base local validada"})
		} else {
			info, err := provision.UpdateDB(ctx, setup.Global, setup.Binary, setup.CacheDir, 20*time.Minute)
			if err != nil {
				return nil, err
			}
			if err := provision.UpdateChecks(ctx, setup.Global, setup.Binary, setup.CacheDir, 10*time.Minute); err != nil {
				setup.Preparations = append(setup.Preparations, report.Preparation{Action: "checks", Status: "failed", Detail: err.Error()})
			} else {
				setup.Preparations = append(setup.Preparations, report.Preparation{Action: "checks", Status: "ok", Detail: "bundle de checks actualizado"})
			}
			setup.DB = info
			setup.Preparations = append(setup.Preparations, report.Preparation{Action: "db", Status: "ok", Detail: "base actualizada"})
		}

	default:
		return nil, fmt.Errorf("modalidad de Trivy desconocida: %q", setup.Mode)
	}

	// El exclusivo se libera antes de pedir el compartido: flock no convierte
	// un bloqueo en otro y pedirlo consigo mismo bloquearía (design §7.4).
	if err := exclusive.Release(); err != nil {
		return nil, err
	}
	shared, err := platform.Acquire(ctx, lockPath, true, 5*time.Minute)
	if err != nil {
		return nil, err
	}
	setup.Shared = shared
	return setup, nil
}
