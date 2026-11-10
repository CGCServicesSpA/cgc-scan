package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/internal/toolchain"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

// toolchainHostEnv permite forzar el uso de los toolchains del equipo. Es una
// salida de emergencia operativa y para pruebas; el valor por defecto es
// automático.
const toolchainHostEnv = "CGC_SCAN_TOOLCHAIN"

// hostToolchainForced informa si el usuario pidió no usar contenedores.
func hostToolchainForced() bool {
	return os.Getenv(toolchainHostEnv) == "host"
}

// prepareAdapterImages resuelve, por unidad y adaptador, la imagen derivada
// sobre la versión del lenguaje del proyecto. Devuelve el contenedor de cada
// unidad, las acciones de preparación y las limitaciones que el reporte debe
// declarar. Un fallo de una imagen no detiene el escaneo: la unidad cae al
// toolchain del host y, si tampoco está, queda omitida con cobertura parcial.
func (a *App) prepareAdapterImages(ctx context.Context, adapterID string, applies func(discovery.Unit) bool,
	ms *manifest.Manifest, disc discovery.Result, allowed map[string]bool, opts scanOptions,
	info runner.DockerInfo, extraMounts []runner.Mount) (map[string]*adapter.Container, []report.Preparation, []string) {

	containers := map[string]*adapter.Container{}
	if hostToolchainForced() || info.Version == "" {
		return containers, nil, nil
	}
	spec, err := ms.Adapter(adapterID)
	if err != nil {
		return containers, nil, nil
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	memo := map[string]*adapter.Container{}
	var prep []report.Preparation
	var limitations []string
	for _, u := range disc.Units {
		if u.Kind == "repository" || !applies(u) || !allowed[u.ID] {
			continue
		}
		ts := toolchain.DetectFor(disc.Root, u, adapterLanguages(adapterID)...)
		if ts.Family() == "" {
			continue
		}
		tag := toolchain.TagFor(ts, adapterID, spec.Version)
		container, ok := memo[tag]
		if !ok {
			img, err := provision.EnsureToolchainImage(ctx, provision.ToolchainOptions{
				DockerBin: "docker", Offline: opts.Offline, NoAutoInstall: opts.NoAutoInstall,
				Arch: info.Arch, HTTPClient: client,
			}, ts, spec)
			if err != nil {
				detail := fmt.Sprintf("unidad %s: %v", u.ID, err)
				prep = append(prep, report.Preparation{Action: "toolchain:" + adapterID, Status: "failed", Detail: detail})
				limitations = append(limitations, "toolchain en contenedor no disponible: "+detail)
				memo[tag] = nil
			} else {
				container = &adapter.Container{
					Image: img.Tag, Root: adapter.ContainerRoot, CacheDir: toolchain.CachePath(), Offline: opts.Offline,
					Mounts: append(append([]runner.Mount{}, extraMounts...),
						runner.Mount{Source: ts.CacheVolume(os.Getuid()), Target: toolchain.CachePath()}),
				}
				detail := fmt.Sprintf("%s con %s", img.Tag, baseDescription(img))
				prep = append(prep, report.Preparation{Action: "toolchain:" + adapterID, Status: "ok", Detail: detail})
				memo[tag] = container
			}
		}
		if container != nil {
			containers[u.ID] = container
		}
	}
	return containers, prep, limitations
}

// containerProvider devuelve la función que consultan los adaptadores.
func containerProvider(containers map[string]*adapter.Container) func(discovery.Unit) *adapter.Container {
	if len(containers) == 0 {
		return nil
	}
	return func(u discovery.Unit) *adapter.Container { return containers[u.ID] }
}

// adapterLanguages acota la detección de versión al lenguaje del adaptador.
func adapterLanguages(adapterID string) []discovery.Language {
	switch adapterID {
	case "govulncheck":
		return []discovery.Language{discovery.Go}
	case "eslint":
		return []discovery.Language{discovery.JavaScript, discovery.TypeScript}
	case "psalm":
		return []discovery.Language{discovery.PHP}
	case "cargo-audit":
		return []discovery.Language{discovery.Rust}
	case "bandit":
		return []discovery.Language{discovery.Python}
	}
	return nil
}

// stageForMount copia una ruta del host a un directorio temporal compartido con
// Docker. Devuelve la ruta original si la copia falla: el montaje puede
// funcionar en equipos donde el directorio de datos sí está compartido.
func stageForMount(stageDir, name, src string) (string, error) {
	if stageDir == "" || src == "" {
		return src, nil
	}
	dst := filepath.Join(stageDir, name)
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		return src, err
	}
	return dst, nil
}

// psalmRunDir deja la configuración de Psalm en el staging cuando hay
// contenedores, para poder montarla.
func psalmRunDir(runDir, stageDir string) string {
	if stageDir == "" {
		return runDir
	}
	return filepath.Join(stageDir, "psalm")
}

// baseDescription resume la base usada para el reporte sin exponer rutas. No
// incluye si la imagen se construyó o se reutilizó: ese dato cambia entre
// ejecuciones idénticas y rompería el determinismo del reporte.
func baseDescription(img provision.ToolchainImage) string {
	if img.Base == "" {
		return "imagen de toolchain no fijada en el manifiesto"
	}
	if img.Digest == "" {
		return fmt.Sprintf("base %s (digest no resuelto, no fijada en el manifiesto)", img.Base)
	}
	return fmt.Sprintf("base %s@%s (no fijada en el manifiesto)", img.Base, img.Digest)
}
