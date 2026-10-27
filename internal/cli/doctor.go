package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/policyfile"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// runDoctor diagnostica sin modificar nada (RF-03): no crea directorios, no
// descarga, no toma bloqueos.
func (a *App) runDoctor(cmd *cobra.Command, format string) error {
	now := a.Now()
	dr := &report.DoctorReport{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Adapters:    map[string]report.DoctorAdapter{},
	}

	cfg := config.Default()
	cfgInfo, err := config.Load(a.Paths.ConfigFile())
	if err == nil {
		cfg = cfgInfo
		if _, statErr := os.Stat(a.Paths.ConfigFile()); statErr == nil {
			dr.Config.Present = true
		}
	} else {
		dr.Config.Error = err.Error()
	}
	dr.Config.Path = a.Paths.ConfigFile()
	dr.Config.TrivyMode = cfg.TrivyMode
	dr.Config.SemgrepEnabled = cfg.SemgrepEnabled
	dr.Config.CacheDir = cfg.CacheDir(a.Paths.TrivyCacheDir())
	dr.Config.DBWarnAfter = cfg.DB.WarnAfter
	dr.Config.DBBlockOffline = cfg.DB.BlockAfterOffline

	info, dockerErr := runner.DetectDocker(cmd.Context())
	if dockerErr == nil {
		dr.Docker = report.DoctorDocker{
			Available: true, Version: info.Version, Arch: info.Arch,
			Context: info.Context, Endpoint: info.Endpoint,
		}
		dr.Isolation = report.DoctorIsolation{Level: "enforced", Reason: "Docker local disponible"}
	} else {
		dr.Docker.Error = dockerErr.Error()
		dr.Isolation = report.DoctorIsolation{Level: "configured", Reason: "sin Docker local; runner global"}
	}

	// Trivy instalado por la CLI.
	state, stateErr := config.LoadState(a.Paths.StateFile())
	var installed *config.Install
	if stateErr == nil {
		for i := range state.Installs {
			if state.Installs[i].Engine == "trivy" {
				installed = &state.Installs[i]
			}
		}
	}
	if installed != nil {
		if _, statErr := os.Stat(installed.Path); statErr == nil {
			dr.Trivy.Installed = true
			dr.Trivy.Path = installed.Path
			dr.Trivy.Version = installed.Version
		} else {
			dr.Trivy.Error = fmt.Sprintf("registro apunta a %s, que no existe", installed.Path)
		}
	} else {
		dr.Trivy.Error = "no hay instalación registrada"
	}
	if dr.Trivy.Installed {
		if db, err := provision.ReadDBInfo(dr.Config.CacheDir); err == nil {
			updated := db.UpdatedAt.UTC().Format(time.RFC3339)
			age := db.AgeSeconds
			schema := db.Schema
			dr.Trivy.DB = &report.DBState{
				Source: db.Source, Status: "offline", UpdatedAt: &updated,
				AgeSeconds: &age, Schema: &schema,
			}
			if cfg.WarnAfter() > 0 && time.Since(db.UpdatedAt) > cfg.WarnAfter() {
				dr.Trivy.DB.Status = "stale"
			} else {
				dr.Trivy.DB.Status = "reused"
			}
		} else {
			dr.Trivy.DB = &report.DBState{Source: "trivy-db", Status: "missing", Detail: err.Error()}
		}
		if home, err := os.UserHomeDir(); err == nil {
			link := filepath.Join(platform.UserBinDir(home), "trivy")
			dr.Trivy.Link = link
			if target, err := os.Readlink(link); err == nil {
				dr.Trivy.LinkOK = target == dr.Trivy.Path
			}
		}
	}

	// Semgrep.
	dr.Semgrep.Enabled = cfg.SemgrepEnabled
	if path, err := exec.LookPath("semgrep"); err == nil {
		dr.Semgrep.Available = true
		dr.Semgrep.Version = commandVersion(cmd.Context(), path, "--version")
	}
	if dr.Semgrep.Enabled && !dr.Semgrep.Available {
		dr.Semgrep.Note = "habilitado en la configuración pero no aprovisionado (H6)"
	}

	// Toolchains de adaptadores.
	dr.Adapters["go"] = checkToolchain(cmd.Context(), "go", "version")
	dr.Adapters["javascript"] = checkToolchain(cmd.Context(), "node", "--version")
	dr.Adapters["typescript"] = dr.Adapters["javascript"]
	dr.Adapters["php"] = checkToolchain(cmd.Context(), "php", "--version")
	dr.Adapters["rust"] = checkToolchain(cmd.Context(), "cargo", "--version")
	dr.Adapters["python"] = checkToolchain(cmd.Context(), "python3", "--version")

	// Política del proyecto actual.
	cwd, _ := os.Getwd()
	pol, polErr := policyfile.Load(cwd, now)
	switch {
	case polErr != nil:
		dr.Policy.Error = polErr.Error()
	case pol.Present:
		dr.Policy.Present = true
		dr.Policy.Path = filepath.Join(cwd, policyfile.FileName)
		dr.Policy.Issues = len(pol.Issues)
	default:
		dr.Policy.Path = filepath.Join(cwd, policyfile.FileName)
	}

	return report.EmitDoctor(a.Stdout, dr, format)
}

func checkToolchain(ctx context.Context, binary, versionFlag string) report.DoctorAdapter {
	path, err := exec.LookPath(binary)
	if err != nil {
		return report.DoctorAdapter{Toolchain: binary, Available: false, Error: "no está en PATH"}
	}
	return report.DoctorAdapter{
		Toolchain: binary,
		Available: true,
		Version:   strings.TrimSpace(commandVersion(ctx, path, versionFlag)),
	}
}

func commandVersion(ctx context.Context, path, flag string) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, flag).CombinedOutput() //nolint:gosec // path proviene de LookPath
	if err != nil {
		return ""
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if len(line) > 120 {
		line = line[:120]
	}
	return line
}
