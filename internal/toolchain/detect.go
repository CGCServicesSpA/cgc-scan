// Package toolchain resuelve la versión del lenguaje que declara un proyecto
// y la imagen de contenedor que corresponde a esa versión. La CLI usa esa
// imagen para ejecutar los adaptadores sin depender de los toolchains del
// equipo.
package toolchain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

// Spec es la versión de lenguaje detectada en una unidad.
type Spec struct {
	Language discovery.Language
	// Version es la versión normalizada, p. ej. 1.22.3, 20.11, 8.2.
	Version string
	// Source nombra el archivo y campo del que se leyó la versión.
	Source string
}

// versionRe acota lo que puede llegar a una referencia de imagen: solo
// dígitos y puntos, nunca texto libre del proyecto.
var versionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,2}$`)

// FindVersion extrae la primera versión numérica de una restricción, p. ej.
// "^20.11.0 || ^22" -> "20.11.0". Devuelve "" si no hay una versión válida.
func FindVersion(s string) string {
	m := regexp.MustCompile(`[0-9]+(?:\.[0-9]+){0,2}`).FindString(s)
	if m == "" {
		return ""
	}
	return m
}

// Detect devuelve el toolchain de la unidad. Si el manifiesto no declara una
// versión, la Spec queda vacía y la CLI usa la imagen por defecto del lenguaje.
func Detect(root string, u discovery.Unit) Spec {
	return DetectFor(root, u,
		discovery.Go, discovery.JavaScript, discovery.TypeScript,
		discovery.PHP, discovery.Rust, discovery.Python)
}

// DetectFor devuelve el toolchain de la unidad restringido a los lenguajes
// indicados. Evita que una unidad mixta (monorepo) entregue al adaptador una
// versión de otro lenguaje.
func DetectFor(root string, u discovery.Unit, langs ...discovery.Language) Spec {
	for _, l := range langs {
		if !hasLanguage(u, l) {
			continue
		}
		if spec, ok := detectOne(root, u, l); ok {
			return spec
		}
		return Spec{Language: l}
	}
	return Spec{}
}

func detectOne(root string, u discovery.Unit, l discovery.Language) (Spec, bool) {
	switch l {
	case discovery.Go:
		return detectGo(root, u)
	case discovery.JavaScript, discovery.TypeScript:
		return detectNode(root, u)
	case discovery.PHP:
		return detectPHP(root, u)
	case discovery.Rust:
		return detectRust(root, u)
	case discovery.Python:
		return detectPython(root, u)
	}
	return Spec{}, false
}

func detectGo(root string, u discovery.Unit) (Spec, bool) {
	manifest := findManifest(u, "go.mod")
	if manifest == "" {
		return Spec{}, false
	}
	data, err := os.ReadFile(filepath.Join(root, manifest))
	if err != nil {
		return Spec{}, false
	}
	best := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		var value string
		switch {
		case strings.HasPrefix(line, "go "):
			value = strings.TrimSpace(strings.TrimPrefix(line, "go "))
		case strings.HasPrefix(line, "toolchain go"):
			value = strings.TrimSpace(strings.TrimPrefix(line, "toolchain go"))
		}
		if value == "" {
			continue
		}
		// Solo el primer campo: un comentario o texto adicional no debe
		// convertirse en parte de una referencia de imagen.
		if fields := strings.Fields(value); len(fields) > 0 {
			value = fields[0]
		}
		if !versionRe.MatchString(value) {
			continue
		}
		if best == "" || compareVersions(value, best) > 0 {
			best = value
		}
	}
	if best == "" {
		return Spec{}, false
	}
	return Spec{Language: discovery.Go, Version: best, Source: manifest}, true
}

func detectNode(root string, u discovery.Unit) (Spec, bool) {
	dir := filepath.Join(root, u.Path)
	for _, name := range []string{".nvmrc", ".node-version"} {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			if v := FindVersion(string(data)); v != "" {
				return Spec{Language: discovery.JavaScript, Version: v, Source: name}, true
			}
		}
	}
	manifest := findManifest(u, "package.json")
	if manifest == "" {
		return Spec{}, false
	}
	data, err := os.ReadFile(filepath.Join(root, manifest))
	if err != nil {
		return Spec{}, false
	}
	var pkg struct {
		Engines struct {
			Node string `json:"node"`
		} `json:"engines"`
		Volta struct {
			Node string `json:"node"`
		} `json:"volta"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return Spec{}, false
	}
	if v := FindVersion(pkg.Engines.Node); v != "" {
		return Spec{Language: discovery.JavaScript, Version: v, Source: manifest + ":engines.node"}, true
	}
	if v := FindVersion(pkg.Volta.Node); v != "" {
		return Spec{Language: discovery.JavaScript, Version: v, Source: manifest + ":volta.node"}, true
	}
	return Spec{}, false
}

func detectPHP(root string, u discovery.Unit) (Spec, bool) {
	manifest := findManifest(u, "composer.json")
	if manifest != "" {
		data, err := os.ReadFile(filepath.Join(root, manifest))
		if err == nil {
			var composer struct {
				Require map[string]any `json:"require"`
				Config  struct {
					Platform map[string]any `json:"platform"`
				} `json:"config"`
			}
			if json.Unmarshal(data, &composer) == nil {
				if v := FindVersion(anyString(composer.Config.Platform["php"])); v != "" {
					return Spec{Language: discovery.PHP, Version: v, Source: manifest + ":config.platform.php"}, true
				}
				if v := FindVersion(anyString(composer.Require["php"])); v != "" {
					return Spec{Language: discovery.PHP, Version: v, Source: manifest + ":require.php"}, true
				}
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, u.Path, ".php-version")); err == nil {
		if v := FindVersion(string(data)); v != "" {
			return Spec{Language: discovery.PHP, Version: v, Source: ".php-version"}, true
		}
	}
	return Spec{}, false
}

func detectRust(root string, u discovery.Unit) (Spec, bool) {
	dir := filepath.Join(root, u.Path)
	if data, err := os.ReadFile(filepath.Join(dir, ".rust-toolchain.toml")); err == nil {
		var f struct {
			Toolchain struct {
				Channel string `toml:"channel"`
			} `toml:"toolchain"`
		}
		if toml.Unmarshal(data, &f) == nil {
			if v := FindVersion(f.Toolchain.Channel); v != "" {
				return Spec{Language: discovery.Rust, Version: v, Source: ".rust-toolchain.toml"}, true
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "rust-toolchain")); err == nil {
		if v := FindVersion(string(data)); v != "" {
			return Spec{Language: discovery.Rust, Version: v, Source: "rust-toolchain"}, true
		}
	}
	manifest := findManifest(u, "Cargo.toml")
	if manifest == "" {
		return Spec{}, false
	}
	data, err := os.ReadFile(filepath.Join(root, manifest))
	if err != nil {
		return Spec{}, false
	}
	var cargo struct {
		Package struct {
			RustVersion string `toml:"rust-version"`
			Edition     string `toml:"edition"`
		} `toml:"package"`
		Workspace struct {
			Package struct {
				RustVersion string `toml:"rust-version"`
			} `toml:"package"`
		} `toml:"workspace"`
	}
	if toml.Unmarshal(data, &cargo) != nil {
		return Spec{}, false
	}
	if v := FindVersion(cargo.Package.RustVersion); v != "" {
		return Spec{Language: discovery.Rust, Version: v, Source: manifest + ":package.rust-version"}, true
	}
	if v := FindVersion(cargo.Workspace.Package.RustVersion); v != "" {
		return Spec{Language: discovery.Rust, Version: v, Source: manifest + ":workspace.package.rust-version"}, true
	}
	if v := editionVersion(cargo.Package.Edition); v != "" {
		return Spec{Language: discovery.Rust, Version: v, Source: manifest + ":package.edition"}, true
	}
	return Spec{}, false
}

// editionVersion traduce la edición de Rust a la versión mínima del toolchain.
func editionVersion(edition string) string {
	switch strings.TrimSpace(edition) {
	case "2015":
		return "1.0"
	case "2018":
		return "1.31"
	case "2021":
		return "1.56"
	case "2024":
		return "1.85"
	}
	return ""
}

func detectPython(root string, u discovery.Unit) (Spec, bool) {
	dir := filepath.Join(root, u.Path)
	for _, name := range []string{".python-version", "runtime.txt"} {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			if v := FindVersion(string(data)); v != "" {
				return Spec{Language: discovery.Python, Version: v, Source: name}, true
			}
		}
	}
	if manifest := findManifest(u, "pyproject.toml"); manifest != "" {
		if data, err := os.ReadFile(filepath.Join(root, manifest)); err == nil {
			var py struct {
				Project struct {
					RequiresPython string `toml:"requires-python"`
				} `toml:"project"`
				Tool struct {
					Poetry struct {
						Dependencies map[string]any `toml:"dependencies"`
					} `toml:"poetry"`
				} `toml:"tool"`
			}
			if toml.Unmarshal(data, &py) == nil {
				if v := FindVersion(py.Project.RequiresPython); v != "" {
					return Spec{Language: discovery.Python, Version: v, Source: manifest + ":project.requires-python"}, true
				}
				if v := FindVersion(anyString(py.Tool.Poetry.Dependencies["python"])); v != "" {
					return Spec{Language: discovery.Python, Version: v, Source: manifest + ":tool.poetry.dependencies.python"}, true
				}
			}
		}
	}
	if manifest := findManifest(u, "Pipfile"); manifest != "" {
		if data, err := os.ReadFile(filepath.Join(root, manifest)); err == nil {
			var pipfile struct {
				Requires struct {
					PythonVersion string `toml:"python_version"`
				} `toml:"requires"`
			}
			if toml.Unmarshal(data, &pipfile) == nil {
				if v := FindVersion(pipfile.Requires.PythonVersion); v != "" {
					return Spec{Language: discovery.Python, Version: v, Source: manifest + ":requires.python_version"}, true
				}
			}
		}
	}
	return Spec{}, false
}

func findManifest(u discovery.Unit, base string) string {
	for _, m := range u.Manifests {
		if filepath.Base(m) == base {
			return m
		}
	}
	return ""
}

func hasLanguage(u discovery.Unit, l discovery.Language) bool {
	for _, x := range u.Languages {
		if x == l {
			return true
		}
	}
	return false
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return ""
	}
}

// compareVersions compara dos versiones numéricas componente a componente.
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] == pb[i] {
			continue
		}
		if pa[i] < pb[i] {
			return -1
		}
		return 1
	}
	return 0
}

func versionParts(v string) [3]int {
	var out [3]int
	for i, p := range strings.Split(v, ".") {
		if i >= 3 {
			break
		}
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	return out
}

// Family devuelve el nombre del lenguaje usado en imágenes y volúmenes.
func (s Spec) Family() string {
	switch s.Language {
	case discovery.Go:
		return "go"
	case discovery.JavaScript, discovery.TypeScript:
		return "node"
	case discovery.PHP:
		return "php"
	case discovery.Rust:
		return "rust"
	case discovery.Python:
		return "python"
	}
	return ""
}

// Images devuelve las imágenes base candidatas, de la más precisa a la más
// general. El aprovisionamiento prueba en orden y falla en voz alta si
// ninguna existe: nunca sustituye la versión del proyecto por otra en
// silencio.
func (s Spec) Images() []string {
	family := s.Family()
	if family == "" {
		return nil
	}
	var parts []string
	if s.Version != "" {
		parts = strings.Split(s.Version, ".")
	}
	var out []string
	add := func(v string) {
		if v == "" {
			return
		}
		for _, x := range out {
			if x == v {
				return
			}
		}
		out = append(out, v)
	}
	switch family {
	case "go":
		if len(parts) >= 3 {
			add("golang:" + strings.Join(parts[:3], "."))
		}
		if len(parts) >= 2 {
			add("golang:" + strings.Join(parts[:2], "."))
		}
		add("golang:1")
	case "node":
		if len(parts) >= 3 {
			add("node:" + strings.Join(parts[:3], "."))
		}
		if len(parts) >= 2 {
			add("node:" + strings.Join(parts[:2], "."))
		}
		if len(parts) >= 1 {
			add("node:" + parts[0])
		}
		add("node:22")
	case "php":
		if len(parts) >= 2 {
			add("php:" + strings.Join(parts[:2], ".") + "-cli")
		}
		if len(parts) >= 1 {
			add("php:" + parts[0] + "-cli")
		}
		add("php:8.3-cli")
	case "rust":
		if len(parts) >= 3 {
			add("rust:" + strings.Join(parts[:3], ".") + "-slim")
		}
		if len(parts) >= 2 {
			add("rust:" + strings.Join(parts[:2], ".") + "-slim")
		}
		add("rust:1-slim")
	case "python":
		if len(parts) >= 3 {
			add("python:" + strings.Join(parts[:3], ".") + "-slim")
		}
		if len(parts) >= 2 {
			add("python:" + strings.Join(parts[:2], ".") + "-slim")
		}
		if len(parts) >= 1 {
			add("python:" + parts[0] + "-slim")
		}
		add("python:3.12-slim")
	}
	return out
}

// CacheVolume devuelve el volumen de caché del lenguaje, propio del usuario.
func (s Spec) CacheVolume(uid int) string {
	family := s.Family()
	if family == "" {
		return ""
	}
	return "cgc-scan-toolchain-" + family + "-" + sanitizeTag(s.Version) + "-" + strconv.Itoa(uid)
}

// CachePath devuelve la ruta de la caché dentro del contenedor.
func CachePath() string { return "/cache" }

func sanitizeTag(s string) string {
	if s == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.TrimLeft(b.String(), ".-")
	if out == "" {
		return "default"
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
