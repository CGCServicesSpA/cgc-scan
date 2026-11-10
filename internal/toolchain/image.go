package toolchain

import (
	"fmt"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/manifest"
	banditassets "github.com/CGCServicesSpA/cgc-scan/manifest/bandit"
	eslintassets "github.com/CGCServicesSpA/cgc-scan/manifest/eslint"
)

// Artifact es un archivo que el aprovisionamiento descarga, verifica y deja en
// el contexto de construcción.
type Artifact struct {
	Name          string
	URL           string
	SHA256        string
	ExtractBinary string
}

// Plan describe cómo construir la imagen de toolchain de un adaptador.
type Plan struct {
	// Tag es la etiqueta determinista de la imagen derivada.
	Tag string
	// BaseCandidates son las imágenes oficiales compatibles, de la más
	// precisa a la más general.
	BaseCandidates []string
	// Template es el Dockerfile con el marcador {{BASE}}.
	Template string
	// Files son archivos embebidos que van al contexto de construcción.
	Files map[string][]byte
	// Artifacts son archivos descargados y verificados por hash.
	Artifacts []Artifact
}

// TagFor construye la etiqueta de la imagen derivada.
func TagFor(spec Spec, adapterID, adapterVersion string) string {
	family := spec.Family()
	if family == "" {
		family = "unknown"
	}
	version := spec.Version
	if version == "" {
		version = "default"
	}
	return "cgc-scan/toolchain:" + sanitizeTag(family+"-"+version+"-"+adapterID+"-"+adapterVersion)
}

// NewPlan prepara la construcción de la imagen de un adaptador para la versión
// detectada. La imagen base se resuelve después, cuando el aprovisionamiento
// conoce el digest efectivo.
func NewPlan(spec Spec, adapter manifest.Adapter, arch string) (Plan, error) {
	family := spec.Family()
	if family == "" {
		return Plan{}, fmt.Errorf("toolchain: lenguaje no soportado para %s", adapter.Version)
	}
	tag := TagFor(spec, adapterID(family), adapter.Version)
	plan := Plan{
		Tag:            tag,
		BaseCandidates: spec.Images(),
		Files:          map[string][]byte{},
	}
	switch family {
	case "go":
		plan.Template = fmt.Sprintf(`FROM {{BASE}} AS cgc-builder
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto GOBIN=/out
RUN go install golang.org/x/vuln/cmd/govulncheck@v%s
FROM {{BASE}}
COPY --from=cgc-builder /out/govulncheck /usr/local/bin/govulncheck
ENTRYPOINT []
CMD ["/bin/sh"]
`, adapter.Version)
	case "node":
		plan.Files["package.json"] = eslintassets.PackageJSON
		plan.Files["package-lock.json"] = eslintassets.LockJSON
		plan.Files["cgc-eslint.config.mjs"] = eslintassets.Config
		plan.Template = `FROM {{BASE}}
ENV NODE_ENV=production npm_config_update_notifier=false
WORKDIR /opt/cgc/eslint
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY cgc-eslint.config.mjs .
ENTRYPOINT []
CMD ["/bin/sh"]
`
	case "php":
		plan.Artifacts = []Artifact{{Name: "psalm.phar", URL: adapter.URL, SHA256: adapter.SHA256}}
		plan.Template = `FROM {{BASE}}
COPY psalm.phar /opt/cgc/psalm.phar
RUN chmod 0755 /opt/cgc/psalm.phar
ENTRYPOINT []
CMD ["/bin/sh"]
`
	case "rust":
		ar, err := adapter.Archive("linux", dockerArch(arch))
		if err != nil {
			return Plan{}, fmt.Errorf("toolchain: %w", err)
		}
		plan.Artifacts = []Artifact{{
			Name: "cargo-audit", URL: ar.URL, SHA256: ar.SHA256, ExtractBinary: "cargo-audit",
		}}
		plan.Template = `FROM {{BASE}}
COPY cargo-audit /usr/local/bin/cargo-audit
RUN chmod 0755 /usr/local/bin/cargo-audit
ENTRYPOINT []
CMD ["/bin/sh"]
`
	case "python":
		plan.Files["requirements.txt"] = banditassets.Requirements
		plan.Template = `FROM {{BASE}}
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /opt/cgc/requirements.txt
RUN pip install --require-hashes --only-binary=:all: -r /opt/cgc/requirements.txt
ENTRYPOINT []
CMD ["/bin/sh"]
`
	default:
		return Plan{}, fmt.Errorf("toolchain: familia %q no soportada", family)
	}
	return plan, nil
}

// Render sustituye la imagen base resuelta (tag@digest) en el Dockerfile.
func (p Plan) Render(baseRef string) []byte {
	return []byte(strings.ReplaceAll(p.Template, "{{BASE}}", baseRef))
}

// adapterID devuelve el identificador del adaptador que corresponde a la
// familia del lenguaje. Cada familia tiene un único motor.
func adapterID(family string) string {
	switch family {
	case "go":
		return "govulncheck"
	case "node":
		return "eslint"
	case "php":
		return "psalm"
	case "rust":
		return "cargo-audit"
	case "python":
		return "bandit"
	}
	return family
}

// dockerArch normaliza la arquitectura del daemon a GOARCH.
func dockerArch(arch string) string {
	switch strings.ToLower(arch) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	}
	return strings.ToLower(arch)
}
