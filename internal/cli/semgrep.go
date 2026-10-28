package cli

import (
	"context"
	"os/exec"
	"path/filepath"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/semgrep"
	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// semgrepEngine prepara Semgrep solo si setup lo habilitó. Cuando está
// desactivado no se descarga, instala ni ejecuta (CA-47).
func (a *App) semgrepEngine(ctx context.Context, ms *manifest.Manifest, cfg config.Config,
	setup *engineSetup, disc discovery.Result, m *masking.Masker, runDir string, opts scanOptions) *orchestrator.Engine {

	if !cfg.SemgrepEnabled {
		return nil
	}
	spec, err := ms.Adapter("semgrep")
	if err != nil {
		return nil
	}
	rulesHost := filepath.Join(runDir, "semgrep-rules")
	count, rulesErr := provision.WriteSemgrepRules(rulesHost)
	rulesDir := rulesHost
	binary := ""
	if rulesErr != nil {
		rulesDir = ""
		count = 0
	}
	host := &runner.Global{Paths: a.Paths}

	if setup.Mode == "docker" {
		eng := orchestrator.Engine{
			ID: "semgrep", Version: spec.Version, Mode: "docker",
			Adapter:   semgrep.New(spec.Version, disc.Root, "/rules", "", "docker", count, m),
			Runner:    &runner.Docker{Image: spec.Image, Volume: setup.Volume, Mounts: []runner.Mount{{Source: rulesHost, Target: "/rules", ReadOnly: true}}},
			Isolation: runner.IsolationEnforced,
			Image:     spec.Image,
		}
		if _, err := provision.EnsureDockerImage(ctx, "docker", spec.Image, !opts.Offline && !opts.NoAutoInstall); err != nil {
			eng.Adapter = semgrep.New(spec.Version, disc.Root, "", "", "docker", 0, m)
		}
		return &eng
	}

	if bin, err := exec.LookPath("semgrep"); err == nil {
		if verr := provision.VerifySemgrepVersion(ctx, bin, spec.Version); verr == nil {
			binary = bin
		}
	}
	return &orchestrator.Engine{
		ID: "semgrep", Version: spec.Version, Mode: "global",
		Adapter:    semgrep.New(spec.Version, disc.Root, rulesDir, binary, "global", count, m),
		Runner:     host,
		Isolation:  runner.IsolationConfigured,
		BinaryPath: binary,
	}
}

// semgrepDisabledReport declara el motor desactivado sin marcar la ejecución
// como incompleta.
func semgrepDisabledReport(ms *manifest.Manifest) *report.EngineReport {
	spec, err := ms.Adapter("semgrep")
	if err != nil {
		return nil
	}
	return &report.EngineReport{
		ID: "semgrep", Version: spec.Version, Status: "disabled", Mode: "none",
		Units:       []report.EngineState{},
		Limitations: []string{"Semgrep CE desactivado en setup; el análisis de código usa los adaptadores de segundo nivel"},
	}
}
