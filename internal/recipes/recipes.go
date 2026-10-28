// Package recipes detecta candidatos de validación en los manifiestos y
// gestiona las recetas confirmadas por el usuario (RF-37, design §9.5).
package recipes

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

// Candidate es una propuesta detectada, nunca una receta de confianza.
type Candidate struct {
	Unit    string `json:"unit"`
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Workdir string `json:"workdir"`
	Origin  string `json:"origin"`
}

// Listing es la vista de `recipes`.
type Listing struct {
	Project    string          `json:"project"`
	Candidates []Candidate     `json:"candidates"`
	Confirmed  []config.Recipe `json:"confirmed"`
}

// Detect construye los candidatos leyendo los manifiestos de cada unidad.
func Detect(root string, units []discovery.Unit) []Candidate {
	var out []Candidate
	add := func(unit, kind, command, workdir, origin string) {
		if !validKind(kind) || strings.TrimSpace(command) == "" {
			return
		}
		for _, c := range out {
			if c.Unit == unit && c.Kind == kind {
				return
			}
		}
		out = append(out, Candidate{Unit: unit, Kind: kind, Command: command, Workdir: workdir, Origin: origin})
	}
	for _, u := range units {
		if u.Kind == "repository" {
			continue
		}
		for _, m := range u.Manifests {
			full := filepath.Join(root, m)
			dir := filepath.Dir(m)
			switch filepath.Base(m) {
			case "go.mod":
				add(u.ID, "test", "go test ./...", dir, "go.mod")
				add(u.ID, "build", "go build ./...", dir, "go.mod")
			case "Cargo.toml":
				add(u.ID, "test", "cargo test", dir, "Cargo.toml")
				add(u.ID, "build", "cargo build", dir, "Cargo.toml")
			case "package.json":
				var pkg struct {
					Scripts map[string]string `json:"scripts"`
				}
				if data, err := os.ReadFile(full); err == nil && json.Unmarshal(data, &pkg) == nil {
					for _, kind := range []string{"test", "build"} {
						if cmd, ok := pkg.Scripts[kind]; ok && strings.TrimSpace(cmd) != "" {
							add(u.ID, kind, "npm run "+kind, dir, "package.json")
						}
					}
				}
			case "composer.json":
				var pkg struct {
					Scripts map[string]any `json:"scripts"`
				}
				if data, err := os.ReadFile(full); err == nil && json.Unmarshal(data, &pkg) == nil {
					for _, kind := range []string{"test", "build"} {
						if _, ok := pkg.Scripts[kind]; ok {
							add(u.ID, kind, "composer run-script "+kind, dir, "composer.json")
						}
					}
				}
			case "pyproject.toml", "requirements.txt", "Pipfile":
				add(u.ID, "test", "pytest", dir, filepath.Base(m))
			}
		}
		// Makefile no es un manifiesto de lenguaje pero declara objetivos.
		if data, err := os.ReadFile(filepath.Join(root, u.Path, "Makefile")); err == nil {
			for _, kind := range []string{"test", "build"} {
				if hasMakeTarget(string(data), kind) {
					add(u.ID, kind, "make "+kind, u.Path, "Makefile")
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Unit == out[j].Unit {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Unit < out[j].Unit
	})
	return out
}

func validKind(k string) bool { return k == "test" || k == "build" }

func hasMakeTarget(content, target string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, target+":") {
			return true
		}
	}
	return false
}

// Confirmed filtra las recetas del usuario para un proyecto.
func Confirmed(cfg config.Config, project string) []config.Recipe {
	out := make([]config.Recipe, 0)
	for _, r := range cfg.Recipes {
		if filepath.Clean(r.Project) == filepath.Clean(project) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Unit < out[j].Unit })
	return out
}

// File es el formato aceptado por `recipes --set`.
type File struct {
	Recipes []config.Recipe `toml:"recipes"`
}

// LoadFile lee las recetas de un archivo del usuario y completa el proyecto.
func LoadFile(path, project string) ([]config.Recipe, error) {
	data, err := platform.ReadFileBounded(path, 1<<20)
	if err != nil {
		return nil, err
	}
	var f File
	dec := toml.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("archivo de recetas inválido: %w", err)
	}
	if len(f.Recipes) == 0 {
		return nil, fmt.Errorf("el archivo no declara recetas")
	}
	for i := range f.Recipes {
		r := &f.Recipes[i]
		if r.Project == "" {
			r.Project = project
		}
		if filepath.Clean(r.Project) != filepath.Clean(project) {
			return nil, fmt.Errorf("recetas[%d].project no coincide con el proyecto actual", i)
		}
		if r.Unit == "" {
			return nil, fmt.Errorf("recetas[%d].unit es obligatorio", i)
		}
		if r.Test == nil && r.Build == nil {
			return nil, fmt.Errorf("recetas[%d] no declara test ni build", i)
		}
	}
	return f.Recipes, nil
}

// Merge reemplaza las recetas del proyecto y conserva las de otros proyectos.
func Merge(cfg *config.Config, project string, entries []config.Recipe) {
	kept := make([]config.Recipe, 0, len(cfg.Recipes))
	for _, r := range cfg.Recipes {
		if filepath.Clean(r.Project) != filepath.Clean(project) {
			kept = append(kept, r)
		}
	}
	kept = append(kept, entries...)
	cfg.Recipes = kept
}

// Clear elimina las recetas del proyecto y devuelve cuántas quitó.
func Clear(cfg *config.Config, project string) int {
	kept := make([]config.Recipe, 0, len(cfg.Recipes))
	removed := 0
	for _, r := range cfg.Recipes {
		if filepath.Clean(r.Project) == filepath.Clean(project) {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	cfg.Recipes = kept
	return removed
}

// JSON serializa la vista.
func (l Listing) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Text renderiza la vista.
func (l Listing) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Proyecto: %s\n", l.Project)
	if len(l.Confirmed) == 0 {
		fmt.Fprintln(&b, "Recetas confirmadas: ninguna")
	} else {
		fmt.Fprintln(&b, "Recetas confirmadas:")
		for _, r := range l.Confirmed {
			fmt.Fprintf(&b, "  %s", r.Unit)
			if r.Test != nil {
				fmt.Fprintf(&b, " test=%q", r.Test.Command)
			}
			if r.Build != nil {
				fmt.Fprintf(&b, " build=%q", r.Build.Command)
			}
			fmt.Fprintln(&b)
		}
	}
	if len(l.Candidates) == 0 {
		fmt.Fprintln(&b, "Candidatos detectados: ninguno")
		return b.String()
	}
	fmt.Fprintln(&b, "Candidatos detectados (propuestas, no recetas):")
	for _, c := range l.Candidates {
		fmt.Fprintf(&b, "  %s %s: %s (%s, %s)\n", c.Unit, c.Kind, c.Command, c.Workdir, c.Origin)
	}
	return b.String()
}
