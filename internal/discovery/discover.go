package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Options configura el descubrimiento.
type Options struct {
	// Target es la ruta absoluta a analizar (puede ser la raíz o un subdirectorio).
	Target string
	// Exclude contiene las exclusiones elegidas ya resueltas por precedencia.
	Exclude []Exclusion
	// ReportOut es el destino de --report-out, que nunca se analiza.
	ReportOut string
}

// discardedDirs son directorios que no se recorren; coinciden con las
// exclusiones intrínsecas y evitan trabajo inútil en árboles grandes.
var discardedDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true,
	"target": true, "dist": true, "build": true, ".next": true, "coverage": true,
}

// Discover recorre el proyecto y devuelve sus unidades y el inventario de
// exclusiones. No ejecuta motores ni escribe nada.
func Discover(ctx context.Context, opts Options) (Result, error) {
	if opts.Target == "" {
		return Result{}, errors.New("descubrimiento: falta la ruta objetivo")
	}
	target, err := filepath.Abs(opts.Target)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return Result{}, fmt.Errorf("abrir %s: %w", target, err)
	}
	if !info.IsDir() {
		return Result{}, fmt.Errorf("%s no es un directorio", target)
	}

	root := DetectRoot(target)
	exclusions := append(IntrinsicExclusions(), opts.Exclude...)
	if opts.ReportOut != "" {
		rel, err := Rel(root, opts.ReportOut)
		if err == nil && rel != "" {
			exclusions = append(exclusions, Exclusion{
				Pattern: rel,
				Origin:  OriginIntrinsic,
				Reason:  "salida de --report-out",
			})
		}
	}

	res := Result{Root: root, Exclusions: exclusions}
	for _, e := range exclusions {
		if e.Origin.Elected() {
			res.Partial = true
		}
	}

	relTarget, relErr := Rel(root, target)
	if relErr != nil {
		relTarget = "."
	}
	units, err := discoverUnits(ctx, root, relTarget)
	if err != nil {
		return Result{}, err
	}
	// Unidad de proyecto: Trivy analiza el árbol objetivo completo una sola
	// vez, de modo que secretos y configuraciones fuera de los módulos también
	// se cubren. La raíz detectada es más amplia y solo sirve para enumerar lo
	// que quedó fuera del objetivo.
	res.Units = append([]Unit{{
		ID: "project", Path: relTarget, Kind: "repository", Languages: unionLanguages(units),
	}}, units...)
	return res, nil
}

// DetectRoot busca la raíz del proyecto desde target hacia arriba. Señales:
// .git, go.work, composer.json y package.json con workspaces (design §9.4).
// Si no hay ninguna, la raíz es el propio target.
func DetectRoot(target string) string {
	dir := target
	for {
		if isRootSignal(dir) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return target
		}
		dir = parent
	}
}

func isRootSignal(dir string) bool {
	if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
		return true
	}
	for _, name := range []string{"go.work", "composer.json"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return hasPackageWorkspaces(filepath.Join(dir, "package.json"))
}

func hasPackageWorkspaces(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var pkg struct {
		Workspaces json.RawMessage `json:"workspaces"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return false
	}
	return len(pkg.Workspaces) > 0
}

// discoverUnits recorre la raíz con os.Root y construye una unidad por
// directorio con manifiesto. Los lenguajes y manifiestos de un mismo
// directorio se agrupan en una sola unidad (monorepos mixtos).
func discoverUnits(ctx context.Context, root, walkRoot string) ([]Unit, error) {
	rt, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("abrir raíz %s: %w", root, err)
	}
	defer func() { _ = rt.Close() }()

	byDir := map[string]*Unit{}
	sourceDir := map[Language]string{}
	add := func(dir string, lang Language, manifest string) {
		u, ok := byDir[dir]
		if !ok {
			u = &Unit{ID: unitID(dir), Path: dir, Kind: kindFor(lang), Languages: []Language{}}
			byDir[dir] = u
		}
		u.Languages = appendUniqueLanguage(u.Languages, lang)
		if manifest != "" {
			u.Manifests = appendUniqueString(u.Manifests, manifest)
		}
	}

	err = fs.WalkDir(rt.FS(), walkRoot, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if p != walkRoot && discardedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		dir := path.Dir(p)
		name := d.Name()
		lang, isManifest, unitKind := classify(name)
		if isManifest && name != "go.work" {
			add(dir, lang, p)
			if unitKind == "module" {
				byDir[dir].Kind = "module"
			}
			return nil
		}
		if lang != Language("") {
			if _, ok := sourceDir[lang]; !ok {
				sourceDir[lang] = dir
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("recorrer %s: %w", root, err)
	}

	// Los lenguajes con código pero sin manifiesto no desaparecen: se ofrece
	// una unidad de directorio para que el adaptador declare su estado.
	for _, lang := range []Language{Go, JavaScript, TypeScript, PHP, Rust, Python} {
		if !languageDetected(byDir, lang) {
			if dir, ok := sourceDir[lang]; ok {
				add(dir, lang, "")
				byDir[dir].Kind = "directory"
			}
		}
	}
	// Un tsconfig sin package.json crea su propia unidad TypeScript.
	units := make([]Unit, 0, len(byDir))
	for _, u := range byDir {
		sort.Slice(u.Languages, func(i, j int) bool { return u.Languages[i] < u.Languages[j] })
		sort.Strings(u.Manifests)
		units = append(units, *u)
	}
	if len(units) == 0 && hasAnySourceFile(rt, walkRoot) {
		units = append(units, Unit{ID: unitID(walkRoot), Path: walkRoot, Kind: "directory"})
	}
	SortUnits(units)
	return units, nil
}

// classify mapea un nombre de archivo a lenguaje, si es manifiesto, y el tipo
// de unidad que implica.
func classify(name string) (Language, bool, string) {
	lower := strings.ToLower(name)
	switch lower {
	case "go.mod":
		return Go, true, "module"
	case "go.work":
		return Go, true, "workspace"
	case "package.json":
		return JavaScript, true, "package"
	case "tsconfig.json":
		return TypeScript, true, "package"
	case "composer.json":
		return PHP, true, "package"
	case "cargo.toml":
		return Rust, true, "package"
	case "pyproject.toml", "pipfile", "setup.py", "setup.cfg":
		return Python, true, "package"
	}
	if strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt") {
		return Python, true, "package"
	}
	for lang, exts := range map[Language][]string{
		Go:         {".go"},
		JavaScript: {".js", ".jsx", ".mjs", ".cjs"},
		TypeScript: {".ts", ".tsx"},
		PHP:        {".php"},
		Rust:       {".rs"},
		Python:     {".py"},
	} {
		for _, ext := range exts {
			if strings.HasSuffix(lower, ext) {
				return lang, false, ""
			}
		}
	}
	return Language(""), false, ""
}

func kindFor(l Language) string {
	switch l {
	case Go, Rust:
		return "module"
	default:
		return "package"
	}
}

func languageDetected(byDir map[string]*Unit, l Language) bool {
	for _, u := range byDir {
		for _, x := range u.Languages {
			if x == l {
				return true
			}
		}
	}
	return false
}

func appendUniqueLanguage(dst []Language, l Language) []Language {
	for _, x := range dst {
		if x == l {
			return dst
		}
	}
	return append(dst, l)
}

func appendUniqueString(dst []string, s string) []string {
	for _, x := range dst {
		if x == s {
			return dst
		}
	}
	return append(dst, s)
}

func hasAnySourceFile(rt *os.Root, walkRoot string) bool {
	found := false
	_ = fs.WalkDir(rt.FS(), walkRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil //nolint:nilerr
		}
		if d.IsDir() {
			if p != walkRoot && discardedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if lang, _, _ := classify(d.Name()); lang != Language("") {
			found = true
		}
		return nil
	})
	return found
}

func unionLanguages(units []Unit) []Language {
	seen := map[Language]bool{}
	var out []Language
	for _, u := range units {
		for _, l := range u.Languages {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func unitID(rel string) string {
	if rel == "." || rel == "" {
		return "root"
	}
	return rel
}

// Rel devuelve p relativo a root con separadores `/`, o "" si está fuera.
func Rel(root, p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s está fuera de %s", p, root)
	}
	return filepath.ToSlash(rel), nil
}

// SortExclusions ordena por patrón y origen para un reporte determinista.
func SortExclusions(in []Exclusion) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Pattern == in[j].Pattern {
			return in[i].Origin < in[j].Origin
		}
		return in[i].Pattern < in[j].Pattern
	})
}
