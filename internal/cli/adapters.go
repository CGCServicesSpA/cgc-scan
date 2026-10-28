package cli

import (
	"context"
	"net/http"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/bandit"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/cargoaudit"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/eslint"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/govulncheck"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/psalm"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// adapterSetup agrupa los motores de adaptadores listos para orquestar.
type adapterSetup struct {
	Engines      []orchestrator.Engine
	DBs          map[string]orchestrator.DBRef
	Preparations []report.Preparation
}

// prepareAdapters aprovisiona solo las herramientas de los lenguajes
// detectados y construye sus motores. Un fallo de aprovisionamiento no detiene
// el escaneo: el adaptador queda omitido y la ejecución incompleta (CA-06).
func (a *App) prepareAdapters(ctx context.Context, ms *manifest.Manifest, disc discovery.Result,
	masker *masking.Masker, opts scanOptions, runDir string) adapterSetup {

	out := adapterSetup{DBs: map[string]orchestrator.DBRef{}}
	host := &runner.Global{Paths: a.Paths}
	lib := &runner.Library{Global: host}

	installs := map[string]provision.AdapterInstall{}
	installAdapter := func(id string) provision.AdapterInstall {
		if _, ok := installs[id]; ok {
			return installs[id]
		}
		res, err := provision.EnsureAdapter(ctx, provision.AdapterOptions{
			Paths: a.Paths, Manifest: ms,
			HTTPClient: &http.Client{Timeout: 10 * time.Minute},
			Offline:    opts.Offline, NoAutoInstall: opts.NoAutoInstall,
		}, id)
		if err != nil {
			out.Preparations = append(out.Preparations, report.Preparation{
				Action: "adapter:" + id, Status: "failed", Detail: err.Error(),
			})
			res = provision.AdapterInstall{ID: id}
		} else {
			status := "ok"
			detail := "reutilizado"
			if res.Installed {
				detail = "instalado y verificado"
			}
			out.Preparations = append(out.Preparations, report.Preparation{Action: "adapter:" + id, Status: status, Detail: detail})
		}
		installs[id] = res
		return res
	}

	hasGo := hasLanguage(disc, discovery.Go)
	hasJS := hasLanguage(disc, discovery.JavaScript) || hasLanguage(disc, discovery.TypeScript)
	hasPHP := hasLanguage(disc, discovery.PHP)
	hasRust := hasLanguage(disc, discovery.Rust)
	hasPython := hasLanguage(disc, discovery.Python)

	if hasGo {
		spec, _ := ms.Adapter("govulncheck")
		goDir := filepath.Join(a.Paths.CacheDir, "go-vulndb")
		info, err := provision.EnsureGoVulnDB(ctx, &http.Client{Timeout: 60 * time.Second}, goDir, opts.Offline)
		if err != nil {
			goDir = ""
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:go-vulndb", Status: "failed", Detail: err.Error()})
		} else {
			out.DBs["govulncheck"] = orchestrator.DBRef{Source: info.Source, Status: info.Status, UpdatedAt: info.UpdatedAt, Detail: info.Detail}
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:go-vulndb", Status: "ok", Detail: info.Status})
		}
		goBin, _ := exec.LookPath("go")
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "govulncheck", Version: spec.Version, Mode: "library",
			Adapter: govulncheck.New(disc.Root, goDir, goBin, masker), Runner: lib,
			Isolation: runner.IsolationConfigured,
		})
	}

	if hasJS {
		spec, _ := ms.Adapter("eslint")
		inst := installAdapter("eslint")
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "eslint", Version: spec.Version, Mode: "global",
			Adapter: eslint.New(inst, disc.Root, masker), Runner: host,
			Isolation: runner.IsolationConfigured, BinaryPath: inst.Node,
		})
	}

	if hasPHP {
		spec, _ := ms.Adapter("psalm")
		inst := installAdapter("psalm")
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "psalm", Version: spec.Version, Mode: "global",
			Adapter: psalm.New(inst, disc.Root, runDir, masker), Runner: host,
			Isolation: runner.IsolationConfigured, BinaryPath: inst.PHP,
		})
	}

	if hasRust {
		spec, _ := ms.Adapter("cargo-audit")
		inst := installAdapter("cargo-audit")
		rustDir := filepath.Join(a.Paths.CacheDir, "rustsec")
		info, err := provision.EnsureRustSecDB(ctx, &http.Client{Timeout: 5 * time.Minute}, rustDir, opts.Offline)
		if err != nil {
			rustDir = ""
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:rustsec", Status: "failed", Detail: err.Error()})
		} else {
			out.DBs["cargo-audit"] = orchestrator.DBRef{Source: info.Source, Status: info.Status, Detail: info.Detail}
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:rustsec", Status: "ok", Detail: info.Status})
		}
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "cargo-audit", Version: spec.Version, Mode: "global",
			Adapter: cargoaudit.New(inst, disc.Root, rustDir, masker), Runner: host,
			Isolation: runner.IsolationConfigured, BinaryPath: filepath.Join(inst.Dir, "cargo-audit"),
		})
	}

	if hasPython {
		spec, _ := ms.Adapter("bandit")
		inst := installAdapter("bandit")
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "bandit", Version: spec.Version, Mode: "global",
			Adapter: bandit.New(inst, disc.Root, masker), Runner: host,
			Isolation: runner.IsolationConfigured, BinaryPath: filepath.Join(inst.Dir, "venv", "bin", "bandit"),
		})
	}
	return out
}

func hasLanguage(d discovery.Result, l discovery.Language) bool {
	for _, u := range d.Units {
		for _, x := range u.Languages {
			if x == l {
				return true
			}
		}
	}
	return false
}
