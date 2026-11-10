package audit

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// CatalogSchemaVersion es la versión del catálogo de clases.
const CatalogSchemaVersion = "audit-catalog-1.0.0"

// Señales que una unidad puede presentar. Se declaran en los datos del
// catálogo, nunca en el código que reparte el trabajo.
const (
	SignalSource    = "source"
	SignalManifest  = "manifest"
	SignalLockfile  = "lockfile"
	SignalCI        = "ci"
	SignalContainer = "container"
	SignalConfig    = "config"
)

var knownSignals = map[string]bool{
	SignalSource: true, SignalManifest: true, SignalLockfile: true,
	SignalCI: true, SignalContainer: true, SignalConfig: true,
}

var classIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// CatalogJSON es el catálogo embebido y versionado.
//
//go:embed catalog.json
var CatalogJSON []byte

// LanguageSpec declara las extensiones de fuente de un lenguaje.
type LanguageSpec struct {
	Extensions []string `json:"extensions"`
}

// FileNameSpec declara archivos reconocidos por nombre.
type FileNameSpec struct {
	FileNames []string `json:"file_names"`
}

// PathPatternSpec declara rutas reconocidas por patrón relativo.
type PathPatternSpec struct {
	PathPatterns []string `json:"path_patterns"`
}

// FilePatternSpec declara nombres de archivo reconocidos por patrón.
type FilePatternSpec struct {
	FilePatterns []string `json:"file_patterns"`
}

// ExtensionSpec declara extensiones de configuración.
type ExtensionSpec struct {
	Extensions []string `json:"extensions"`
}

// Signals agrupa las señales declaradas.
type Signals struct {
	Manifest  FileNameSpec    `json:"manifest"`
	Lockfile  FileNameSpec    `json:"lockfile"`
	CI        PathPatternSpec `json:"ci"`
	Container FilePatternSpec `json:"container"`
	Config    ExtensionSpec   `json:"config"`
}

// Limits acota el reconocimiento para que el reparto sea barato y estable.
type Limits struct {
	MaxFilesScanned       int `json:"max_files_scanned"`
	MaxStartingPaths      int `json:"max_starting_paths"`
	MaxUnitsPerAssignment int `json:"max_units_per_assignment"`
}

// Class describe una clase de ataque concreta.
type Class struct {
	ID        string   `json:"id"`
	Domain    string   `json:"domain"`
	Boundary  string   `json:"boundary"`
	Title     string   `json:"title"`
	Priority  int      `json:"priority"`
	Languages []string `json:"languages"`
	Requires  []string `json:"requires"`
	Invariant string   `json:"invariant"`
	Checks    []string `json:"checks"`
	Source    string   `json:"source"`
}

// Catalog es el conjunto versionado de clases y señales.
type Catalog struct {
	SchemaVersion string                  `json:"schema_version"`
	Description   string                  `json:"description"`
	Limits        Limits                  `json:"limits"`
	IgnoreDirs    []string                `json:"ignore_dirs"`
	Languages     map[string]LanguageSpec `json:"languages"`
	Signals       Signals                 `json:"signals"`
	Classes       []Class                 `json:"classes"`
}

// LoadCatalog decodifica y valida el catálogo embebido.
func LoadCatalog() (*Catalog, error) {
	var c Catalog
	dec := json.NewDecoder(strings.NewReader(string(CatalogJSON)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("catálogo de auditoría inválido: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate comprueba la coherencia del catálogo.
func (c *Catalog) Validate() error {
	if c == nil {
		return fmt.Errorf("catálogo nil")
	}
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	if c.SchemaVersion != CatalogSchemaVersion {
		add("schema_version %q, se esperaba %q", c.SchemaVersion, CatalogSchemaVersion)
	}
	if c.Limits.MaxFilesScanned < 1 {
		add("limits.max_files_scanned debe ser positivo")
	}
	if c.Limits.MaxStartingPaths < 1 {
		add("limits.max_starting_paths debe ser positivo")
	}
	if c.Limits.MaxUnitsPerAssignment < 1 {
		add("limits.max_units_per_assignment debe ser positivo")
	}
	if len(c.IgnoreDirs) == 0 {
		add("ignore_dirs vacío")
	}
	if len(c.Languages) == 0 {
		add("languages vacío")
	}
	for name, spec := range c.Languages {
		if len(spec.Extensions) == 0 {
			add("lenguaje %q sin extensiones", name)
		}
		for _, ext := range spec.Extensions {
			if !strings.HasPrefix(ext, ".") {
				add("lenguaje %q: extensión inválida %q", name, ext)
			}
		}
	}
	if len(c.Signals.Manifest.FileNames) == 0 {
		add("signals.manifest.file_names vacío")
	}
	if len(c.Signals.Lockfile.FileNames) == 0 {
		add("signals.lockfile.file_names vacío")
	}
	if len(c.Signals.CI.PathPatterns) == 0 {
		add("signals.ci.path_patterns vacío")
	}
	if len(c.Signals.Container.FilePatterns) == 0 {
		add("signals.container.file_patterns vacío")
	}
	if len(c.Signals.Config.Extensions) == 0 {
		add("signals.config.extensions vacío")
	}
	if len(c.Classes) == 0 {
		add("classes vacío")
	}
	seen := map[string]bool{}
	for i, class := range c.Classes {
		at := fmt.Sprintf("classes[%d]", i)
		if !classIDPattern.MatchString(class.ID) {
			add("%s: id inválido %q", at, class.ID)
		}
		if seen[class.ID] {
			add("clase duplicada: %s", class.ID)
		}
		seen[class.ID] = true
		if strings.TrimSpace(class.Domain) == "" || strings.TrimSpace(class.Boundary) == "" ||
			strings.TrimSpace(class.Title) == "" || strings.TrimSpace(class.Invariant) == "" {
			add("%s (%s): domain, boundary, title e invariant son obligatorios", at, class.ID)
		}
		if class.Priority < 1 {
			add("%s (%s): priority debe ser positivo", at, class.ID)
		}
		if len(class.Languages) == 0 {
			add("%s (%s): languages vacío", at, class.ID)
		}
		for _, lang := range class.Languages {
			if lang == "any" {
				continue
			}
			if _, ok := c.Languages[lang]; !ok {
				add("%s (%s): lenguaje desconocido %q", at, class.ID, lang)
			}
		}
		if len(class.Requires) == 0 {
			add("%s (%s): requires vacío", at, class.ID)
		}
		for _, req := range class.Requires {
			if !knownSignals[req] {
				add("%s (%s): señal desconocida %q", at, class.ID, req)
			}
		}
		if len(class.Checks) == 0 {
			add("%s (%s): checks vacío", at, class.ID)
		}
		if strings.TrimSpace(class.Source) == "" {
			add("%s (%s): source es obligatorio para la atribución", at, class.ID)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("catálogo de auditoría inválido: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ClassByID devuelve la clase con ese identificador.
func (c *Catalog) ClassByID(id string) *Class {
	for i := range c.Classes {
		if c.Classes[i].ID == id {
			return &c.Classes[i]
		}
	}
	return nil
}

// applicableClasses devuelve las clases que aplican a una unidad, ordenadas por
// prioridad y luego por identificador.
func (c *Catalog) applicableClasses(unitLanguages []string, signals map[string][]string) []Class {
	langs := map[string]bool{}
	for _, l := range unitLanguages {
		langs[l] = true
	}
	out := make([]Class, 0, len(c.Classes))
	for _, class := range c.Classes {
		if !languageApplies(class.Languages, langs) {
			continue
		}
		if !signalsApply(class.Requires, signals) {
			continue
		}
		out = append(out, class)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func languageApplies(required []string, unit map[string]bool) bool {
	for _, lang := range required {
		if lang == "any" {
			return true
		}
		if unit[lang] {
			return true
		}
	}
	return false
}

func signalsApply(requires []string, signals map[string][]string) bool {
	for _, req := range requires {
		if len(signals[req]) > 0 {
			return true
		}
	}
	return false
}
