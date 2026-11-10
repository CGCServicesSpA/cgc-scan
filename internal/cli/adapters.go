package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/bandit"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/cargoaudit"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/eslint"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/govulncheck"
	"github.com/CGCServicesSpA/cgc-scan/internal/adapter/psalm"
	"github.com/CGCServicesSpA/cgc-scan/internal/config"
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
	// Limitations acumula lo que el reporte debe declarar sobre la forma de
	// ejecución de los adaptadores (contenedor con red, imagen no fijada).
	Limitations []string
	// StagingDir contiene copias de bases y configuraciones para montarlas en
	// contenedores. Vive fuera del proyecto y se elimina al terminar.
	StagingDir string
}

// prepareAdapters aprovisiona solo las herramientas de los lenguajes
// detectados y construye sus motores. Un fallo de aprovisionamiento no detiene
// el escaneo: el adaptador queda omitido y la ejecución incompleta (CA-06).
//
// Si el daemon de Docker está disponible, los adaptadores se ejecutan dentro
// de una imagen derivada de la imagen oficial del lenguaje y de la versión que
// declara el proyecto. El directorio se monta en solo lectura y la red queda
// habilitada para resolver dependencias, por lo que el aislamiento se declara
// configured. Sin Docker, se mantiene el toolchain del host.
func (a *App) prepareAdapters(ctx context.Context, ms *manifest.Manifest, disc discovery.Result,
	masker *masking.Masker, opts scanOptions, runDir string, cfg config.Config, allowedUnits map[string]bool) adapterSetup {

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

	// Solo se consulta el daemon si hay algún adaptador que ejecutar.
	var (
		dockerInfo runner.DockerInfo
		container  *runner.Docker
		stageDir   string
	)
	if hasGo || hasJS || hasPHP || hasRust || hasPython {
		dockerInfo, _ = runner.DetectDocker(ctx)
		if dockerInfo.Version != "" {
			container = &runner.Docker{DockerBin: "docker", Network: true}
		}
	}
	// Las bases y configuraciones que el contenedor necesita se montan desde
	// un directorio temporal: el directorio de datos de la CLI (p. ej.
	// ~/Library/Application Support en macOS) no siempre está compartido con
	// el daemon de Docker.
	if container != nil {
		if dir, err := os.MkdirTemp("", "cgc-scan-stage-*"); err == nil {
			stageDir = dir
			out.StagingDir = dir
		}
	}

	if hasGo {
		spec, _ := ms.Adapter("govulncheck")
		goDir := filepath.Join(a.Paths.CacheDir, "go-vulndb")
		info, err := provision.EnsureGoVulnDBWithRefresh(ctx, &http.Client{Timeout: 60 * time.Second}, goDir, opts.Offline, cfg.RefreshAfter())
		if err != nil {
			goDir = ""
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:go-vulndb", Status: "failed", Detail: err.Error()})
		} else {
			out.DBs["govulncheck"] = orchestrator.DBRef{Source: info.Source, Status: info.Status, UpdatedAt: info.UpdatedAt, Detail: info.Detail}
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:go-vulndb", Status: "ok", Detail: info.Status})
		}
		goBin, _ := findGoBinary()
		ad := govulncheck.New(disc.Root, goDir, goBin, masker)
		var mounts []runner.Mount
		if goDir != "" {
			mounted, err := stageForMount(stageDir, "go-vulndb", goDir)
			if err != nil {
				out.Preparations = append(out.Preparations, report.Preparation{Action: "stage:govulncheck", Status: "failed", Detail: err.Error()})
			}
			mounts = append(mounts, runner.Mount{Source: mounted, Target: govulncheck.ContainerDBDir, ReadOnly: true})
		}
		images, prep, lims := a.prepareAdapterImages(ctx, "govulncheck", ad.Applies, ms, disc, allowedUnits, opts, dockerInfo, mounts)
		ad.ContainerFor = containerProvider(images)
		out.Preparations = append(out.Preparations, prep...)
		out.Limitations = append(out.Limitations, lims...)
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "govulncheck", Version: spec.Version, Mode: engineMode("library", images),
			Adapter: ad, Runner: lib, ContainerRunner: containerFor(images, container),
			Isolation: runner.IsolationConfigured, CacheMode: "deps", DBKey: dbRefKey(out.DBs["govulncheck"]),
			Image: singleImage(images),
		})
	}

	if hasJS {
		spec, _ := ms.Adapter("eslint")
		ad := eslint.New(provision.AdapterInstall{ID: "eslint", Version: spec.Version}, disc.Root, masker)
		images, prep, lims := a.prepareAdapterImages(ctx, "eslint", ad.Applies, ms, disc, allowedUnits, opts, dockerInfo, nil)
		if applicableCount(ad.Applies, disc, allowedUnits) > 0 && (needsHostInstall(images, ad.Applies, disc, allowedUnits) || len(images) == 0) {
			ad.Install = installAdapter("eslint")
		}
		ad.ContainerFor = containerProvider(images)
		out.Preparations = append(out.Preparations, prep...)
		out.Limitations = append(out.Limitations, lims...)
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "eslint", Version: spec.Version, Mode: engineMode("global", images),
			Adapter: ad, Runner: host, ContainerRunner: containerFor(images, container),
			Isolation: runner.IsolationConfigured, BinaryPath: ad.Install.Node, CacheMode: "source",
			Image: singleImage(images),
		})
	}

	if hasPHP {
		spec, _ := ms.Adapter("psalm")
		ad := psalm.New(provision.AdapterInstall{ID: "psalm", Version: spec.Version}, disc.Root, psalmRunDir(runDir, stageDir), masker)
		images, prep, lims := a.prepareAdapterImages(ctx, "psalm", ad.Applies, ms, disc, allowedUnits, opts, dockerInfo, nil)
		if applicableCount(ad.Applies, disc, allowedUnits) > 0 && (needsHostInstall(images, ad.Applies, disc, allowedUnits) || len(images) == 0) {
			ad.Install = installAdapter("psalm")
		}
		ad.ContainerFor = containerProvider(images)
		out.Preparations = append(out.Preparations, prep...)
		out.Limitations = append(out.Limitations, lims...)
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "psalm", Version: spec.Version, Mode: engineMode("global", images),
			Adapter: ad, Runner: host, ContainerRunner: containerFor(images, container),
			Isolation: runner.IsolationConfigured, BinaryPath: ad.Install.PHP, CacheMode: "source",
			Image: singleImage(images),
		})
	}

	if hasRust {
		spec, _ := ms.Adapter("cargo-audit")
		rustDir := filepath.Join(a.Paths.CacheDir, "rustsec")
		info, err := provision.EnsureRustSecDB(ctx, &http.Client{Timeout: 5 * time.Minute}, rustDir, opts.Offline)
		if err != nil {
			rustDir = ""
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:rustsec", Status: "failed", Detail: err.Error()})
		} else {
			out.DBs["cargo-audit"] = orchestrator.DBRef{Source: info.Source, Status: info.Status, Detail: info.Detail}
			out.Preparations = append(out.Preparations, report.Preparation{Action: "db:rustsec", Status: "ok", Detail: info.Status})
		}
		ad := cargoaudit.New(provision.AdapterInstall{ID: "cargo-audit", Version: spec.Version}, disc.Root, rustDir, masker)
		var mounts []runner.Mount
		if rustDir != "" {
			mounted, err := stageForMount(stageDir, "rustsec", rustDir)
			if err != nil {
				out.Preparations = append(out.Preparations, report.Preparation{Action: "stage:cargo-audit", Status: "failed", Detail: err.Error()})
			}
			mounts = append(mounts, runner.Mount{Source: mounted, Target: cargoaudit.ContainerDB, ReadOnly: true})
		}
		images, prep, lims := a.prepareAdapterImages(ctx, "cargo-audit", ad.Applies, ms, disc, allowedUnits, opts, dockerInfo, mounts)
		if applicableCount(ad.Applies, disc, allowedUnits) > 0 && (needsHostInstall(images, ad.Applies, disc, allowedUnits) || len(images) == 0) {
			ad.Install = installAdapter("cargo-audit")
		}
		ad.ContainerFor = containerProvider(images)
		out.Preparations = append(out.Preparations, prep...)
		out.Limitations = append(out.Limitations, lims...)
		binaryPath := ""
		if ad.Install.Dir != "" {
			binaryPath = filepath.Join(ad.Install.Dir, "cargo-audit")
		}
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "cargo-audit", Version: spec.Version, Mode: engineMode("global", images),
			Adapter: ad, Runner: host, ContainerRunner: containerFor(images, container),
			Isolation: runner.IsolationConfigured, BinaryPath: binaryPath,
			CacheMode: "deps", DBKey: dbRefKey(out.DBs["cargo-audit"]), Image: singleImage(images),
		})
	}

	if hasPython {
		spec, _ := ms.Adapter("bandit")
		ad := bandit.New(provision.AdapterInstall{ID: "bandit", Version: spec.Version}, disc.Root, masker)
		images, prep, lims := a.prepareAdapterImages(ctx, "bandit", ad.Applies, ms, disc, allowedUnits, opts, dockerInfo, nil)
		if applicableCount(ad.Applies, disc, allowedUnits) > 0 && (needsHostInstall(images, ad.Applies, disc, allowedUnits) || len(images) == 0) {
			ad.Install = installAdapter("bandit")
		}
		ad.ContainerFor = containerProvider(images)
		out.Preparations = append(out.Preparations, prep...)
		out.Limitations = append(out.Limitations, lims...)
		binaryPath := ""
		if ad.Install.Dir != "" {
			binaryPath = filepath.Join(ad.Install.Dir, "venv", "bin", "bandit")
		}
		out.Engines = append(out.Engines, orchestrator.Engine{
			ID: "bandit", Version: spec.Version, Mode: engineMode("global", images),
			Adapter: ad, Runner: host, ContainerRunner: containerFor(images, container),
			Isolation: runner.IsolationConfigured, BinaryPath: binaryPath, CacheMode: "source",
			Image: singleImage(images),
		})
	}
	if anyContainer(out.Engines) {
		if opts.Offline {
			out.Limitations = append(out.Limitations,
				"adaptadores en contenedores de toolchain sin red (--offline)")
		} else {
			out.Limitations = append(out.Limitations,
				"adaptadores en contenedores de toolchain: la red se habilita para resolver dependencias del proyecto (aislamiento configured)")
		}
	}
	return out
}

// engineMode declara la forma de ejecución dominante del motor. Las imágenes
// de toolchain se ejecutan con el runner Docker, así que el modo es docker.
func engineMode(hostMode string, images map[string]*adapter.Container) string {
	if len(images) > 0 {
		return "docker"
	}
	return hostMode
}

// containerFor devuelve el runner de contenedores si hay alguna imagen.
func containerFor(images map[string]*adapter.Container, d *runner.Docker) runner.Runner {
	if len(images) == 0 || d == nil {
		return nil
	}
	return d
}

// singleImage devuelve la etiqueta cuando todas las unidades comparten imagen.
func singleImage(images map[string]*adapter.Container) string {
	tag := ""
	for _, c := range images {
		if tag == "" {
			tag = c.Image
			continue
		}
		if tag != c.Image {
			return ""
		}
	}
	return tag
}

// applicableCount cuenta las unidades del plan que el adaptador cubre.
func applicableCount(applies func(discovery.Unit) bool, disc discovery.Result, allowed map[string]bool) int {
	n := 0
	for _, u := range disc.Units {
		if u.Kind != "repository" && applies(u) && allowed[u.ID] {
			n++
		}
	}
	return n
}

// needsHostInstall informa si alguna unidad aplicable no tiene imagen.
func needsHostInstall(images map[string]*adapter.Container, applies func(discovery.Unit) bool,
	disc discovery.Result, allowed map[string]bool) bool {
	for _, u := range disc.Units {
		if u.Kind == "repository" || !applies(u) || !allowed[u.ID] {
			continue
		}
		if _, ok := images[u.ID]; !ok {
			return true
		}
	}
	return false
}

// anyContainer informa si algún motor usa imágenes de toolchain.
func anyContainer(engines []orchestrator.Engine) bool {
	for _, e := range engines {
		if e.Mode == "docker" {
			return true
		}
	}
	return false
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

func dbRefKey(ref orchestrator.DBRef) string {
	return fmt.Sprintf("%s|%s", ref.Source, ref.UpdatedAt.UTC().Format(time.RFC3339Nano))
}

// findGoBinary prefiere el binario del GOROOT con el que se compiló la CLI.
// Un `go` de PATH puede ser un envoltorio que intente descargar otro
// toolchain y, con GOPROXY=off, falle antes de analizar el proyecto.
func findGoBinary() (string, error) {
	if root := runtime.GOROOT(); root != "" {
		candidate := filepath.Join(root, "bin", "go")
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return exec.LookPath("go")
}
