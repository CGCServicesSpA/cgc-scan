// Package projectstate guarda el estado local de un proyecto analizado:
// último reporte, línea base, índice de huellas y resultados por unidad.
// Vive en la caché de la CLI, nunca dentro del proyecto.
package projectstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// Schema es la versión del formato de estado del proyecto.
const Schema = 1

// ResultSchema es la versión de cada resultado por unidad y motor.
const ResultSchema = 1

// ErrNoReport indica que todavía no hay un reporte guardado.
var ErrNoReport = errors.New("no hay un reporte guardado para este proyecto; ejecuta cgc-scan scan o cgc-scan agent")

// ErrNoBaseline indica que no hay línea base.
var ErrNoBaseline = errors.New("no hay línea base guardada; ejecuta cgc-scan baseline set o cgc-scan agent")

// Store da acceso al directorio de estado de un proyecto.
type Store struct {
	dir string
}

// Open resuelve el directorio de estado de root. No lo crea hasta escribir.
func Open(paths platform.Paths, root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("projectstate: falta la raíz del proyecto")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	id := sanitize(report.LocalID(abs))
	return &Store{dir: filepath.Join(paths.CacheDir, "projects", id)}, nil
}

// Dir es la raíz del estado del proyecto.
func (s *Store) Dir() string { return s.dir }

// LatestPath es la ruta del último reporte canónico.
func (s *Store) LatestPath() string { return filepath.Join(s.dir, "latest.json") }

// BaselinePath es la ruta de la línea base.
func (s *Store) BaselinePath() string { return filepath.Join(s.dir, "baseline.json") }

// IndexPath es la ruta del índice de huellas.
func (s *Store) IndexPath() string { return filepath.Join(s.dir, "index.json") }

// HasLatest informa si existe un reporte guardado.
func (s *Store) HasLatest() bool {
	info, err := os.Stat(s.LatestPath())
	return err == nil && info.Mode().IsRegular()
}

// HasBaseline informa si existe una línea base.
func (s *Store) HasBaseline() bool {
	info, err := os.Stat(s.BaselinePath())
	return err == nil && info.Mode().IsRegular()
}

// LoadLatest lee y valida el último reporte.
func (s *Store) LoadLatest() (*report.Document, error) {
	return s.loadDocument(s.LatestPath(), ErrNoReport)
}

// SaveLatest escribe el último reporte de forma atómica y privada.
func (s *Store) SaveLatest(doc *report.Document) error {
	return s.saveDocument(s.LatestPath(), doc)
}

// LoadBaseline lee y valida la línea base.
func (s *Store) LoadBaseline() (*report.Document, error) {
	return s.loadDocument(s.BaselinePath(), ErrNoBaseline)
}

// SaveBaseline escribe la línea base de forma atómica y privada.
func (s *Store) SaveBaseline(doc *report.Document) error {
	return s.saveDocument(s.BaselinePath(), doc)
}

// ClearBaseline elimina la línea base. No falla si no existe.
func (s *Store) ClearBaseline() error {
	err := os.Remove(s.BaselinePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) loadDocument(path string, missing error) (*report.Document, error) {
	data, err := platform.ReadFileBounded(path, 64<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, missing
		}
		return nil, fmt.Errorf("leer estado del proyecto: %w", err)
	}
	if err := report.Validate(data); err != nil {
		return nil, fmt.Errorf("estado del proyecto inválido: %w", err)
	}
	return report.Decode(data)
}

func (s *Store) saveDocument(path string, doc *report.Document) error {
	if doc == nil {
		return errors.New("projectstate: documento nulo")
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := platform.WritePrivateFile(path, data); err != nil {
		return fmt.Errorf("guardar estado del proyecto: %w", err)
	}
	return nil
}

// IndexEntry describe el grupo, la unidad y los motores de una huella.
type IndexEntry struct {
	Group   string   `json:"group,omitempty"`
	Unit    string   `json:"unit"`
	Engines []string `json:"engines"`
	Kind    string   `json:"kind"`
}

// Index mapea huellas a su ubicación de remediación.
type Index struct {
	Schema    int                   `json:"schema"`
	Project   string                `json:"project"`
	RunID     string                `json:"run_id"`
	UpdatedAt string                `json:"updated_at"`
	Findings  map[string]IndexEntry `json:"findings"`
}

// BuildIndex construye el índice a partir del reporte. La unidad se infiere
// de la ruta más específica de target.units; si no hay coincidencia se usa la
// unidad de la verificación o "project".
func BuildIndex(doc *report.Document) Index {
	idx := Index{
		Schema: Schema, Project: doc.Target.Root, RunID: doc.Run.ID,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:  map[string]IndexEntry{},
	}
	groups := map[string]string{}
	for _, g := range doc.RemediationGroups {
		for _, fp := range g.Fixes {
			groups[fp] = g.ID
		}
	}
	for i := range doc.Findings {
		f := &doc.Findings[i]
		engines := make([]string, 0, len(f.Sources))
		for _, src := range f.Sources {
			if src.Engine == "" {
				continue
			}
			engines = append(engines, src.Engine)
		}
		sort.Strings(engines)
		engines = dedupe(engines)
		unit := UnitForFinding(doc, f)
		idx.Findings[f.Fingerprint] = IndexEntry{
			Group: groups[f.Fingerprint], Unit: unit, Engines: engines, Kind: string(f.Kind),
		}
	}
	return idx
}

// UnitForFinding elige la unidad más específica que contiene la ruta.
func UnitForFinding(doc *report.Document, f *normalize.Finding) string {
	path := ""
	if len(f.Locations) > 0 {
		path = f.Locations[0].Path
	}
	bestID, bestPath, bestRepo := "", "", true
	for _, u := range doc.Target.Units {
		up := strings.TrimSuffix(filepath.ToSlash(u.Path), "/")
		if up == "" {
			up = "."
		}
		contains := up == "." || up == "" || path == up || strings.HasPrefix(path, up+"/")
		if !contains {
			continue
		}
		repo := u.Kind == "repository"
		switch {
		case len(up) > len(bestPath):
		case len(up) == len(bestPath) && bestRepo && !repo:
		default:
			continue
		}
		bestID, bestPath, bestRepo = u.ID, up, repo
	}
	if bestID != "" {
		return bestID
	}
	if f.Verification != nil && f.Verification.Unit != "" {
		return f.Verification.Unit
	}
	return "project"
}

// SaveIndex escribe index.json de forma atómica y privada.
func (s *Store) SaveIndex(idx Index) error {
	idx.Schema = Schema
	if idx.Findings == nil {
		idx.Findings = map[string]IndexEntry{}
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := platform.WritePrivateFile(s.IndexPath(), data); err != nil {
		return fmt.Errorf("guardar índice del proyecto: %w", err)
	}
	return nil
}

// LoadIndex lee index.json; si no existe devuelve un índice vacío válido.
func (s *Store) LoadIndex() (Index, error) {
	data, err := platform.ReadFileBounded(s.IndexPath(), 16<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Index{Schema: Schema, Findings: map[string]IndexEntry{}}, nil
		}
		return Index{}, err
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return Index{}, fmt.Errorf("índice del proyecto inválido: %w", err)
	}
	if idx.Schema != Schema {
		return Index{}, fmt.Errorf("índice del proyecto con esquema %d, se esperaba %d", idx.Schema, Schema)
	}
	if idx.Findings == nil {
		idx.Findings = map[string]IndexEntry{}
	}
	return idx, nil
}

// UnitResult es el resultado guardado de un motor en una unidad.
type UnitResult struct {
	Schema   int                 `json:"schema"`
	Engine   string              `json:"engine"`
	Unit     string              `json:"unit"`
	Status   string              `json:"status"`
	Reason   string              `json:"reason,omitempty"`
	Key      string              `json:"cache_key"`
	At       time.Time           `json:"saved_at"`
	Findings []normalize.Finding `json:"findings"`
}

// SaveUnit guarda el resultado de un motor en una unidad.
func (s *Store) SaveUnit(res UnitResult) error {
	if res.Engine == "" || res.Unit == "" {
		return errors.New("projectstate: motor y unidad son obligatorios")
	}
	res.Schema = ResultSchema
	if res.At.IsZero() {
		res.At = time.Now().UTC()
	}
	if res.Findings == nil {
		res.Findings = []normalize.Finding{}
	}
	path := filepath.Join(s.dir, "units", sanitize(res.Unit)+"."+sanitize(res.Engine)+".json")
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := platform.WritePrivateFile(path, data); err != nil {
		return fmt.Errorf("guardar resultado de unidad: %w", err)
	}
	return nil
}

// LoadUnit lee el resultado de un motor en una unidad.
func (s *Store) LoadUnit(engine, unit string) (UnitResult, error) {
	path := filepath.Join(s.dir, "units", sanitize(unit)+"."+sanitize(engine)+".json")
	data, err := platform.ReadFileBounded(path, 64<<20)
	if err != nil {
		return UnitResult{}, err
	}
	var res UnitResult
	if err := json.Unmarshal(data, &res); err != nil {
		return UnitResult{}, fmt.Errorf("resultado de unidad inválido: %w", err)
	}
	return res, nil
}

func sanitize(s string) string {
	s = strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(s)
	s = strings.Trim(s, ".")
	if s == "" {
		return "_"
	}
	return s
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := in[:0]
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
