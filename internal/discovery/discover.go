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

	units, err := discoverUnits(ctx, root, target)
	if err != nil {
		return Result{}, err
	}
	// Unidad de proyecto: Trivy analiza el árbol completo una sola vez, de modo
	// que secretos y configuraciones fuera de los módulos también se cubren.
	if rel, err := Rel(root, target); err == nil {
		res.Units = append([]Unit{{
			ID: "project", Path: rel, Kind: "repository", Languages: unionLanguages(units),
		}}, units...)
	} else {
		res.Units = units
	}
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

// discoverUnits recorre la raíz con os.Root. Solo se consideran unidades los
// directorios con go.mod; el resto del proyecto queda fuera del inventario y,
// por lo tanto, no se presenta como analizado.
func discoverUnits(ctx context.Context, root, target string) ([]Unit, error) {
	rt, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("abrir raíz %s: %w", root, err)
	}
	defer func() { _ = rt.Close() }()

	var units []Unit
	err = fs.WalkDir(rt.FS(), ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Un enlace roto o un permiso denegado no debe tumbar el
			// descubrimiento: se omite y la cobertura lo refleja.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if p != "." && discardedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		dir := path.Dir(p)
		if dir == "." {
			dir = "."
		}
		units = append(units, Unit{
			ID:        unitID(dir),
			Path:      dir,
			Kind:      "module",
			Languages: []Language{Go},
			Manifests: []string{p},
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("recorrer %s: %w", root, err)
	}
	if len(units) == 0 {
		// Sin manifiestos Go, si hay archivos .go se ofrece una unidad de
		// directorio para no ocultar código analizable.
		if hasGoFiles(rt) {
			rel, _ := Rel(root, target)
			if rel == "" {
				rel = "."
			}
			units = append(units, Unit{ID: unitID(rel), Path: rel, Kind: "directory", Languages: []Language{Go}})
		}
	}
	SortUnits(units)
	return units, nil
}

func hasGoFiles(rt *os.Root) bool {
	found := false
	_ = fs.WalkDir(rt.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil //nolint:nilerr // un error de recorrido solo omite el archivo
		}
		if d.IsDir() {
			if p != "." && discardedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") {
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
