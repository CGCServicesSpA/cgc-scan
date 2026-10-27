// Package report define el contrato del reporte y sus renderizadores.
package report

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

// Document es el reporte completo.
type Document struct {
	SchemaVersion string              `json:"schema_version"`
	Run           Run                 `json:"run"`
	Target        Target              `json:"target"`
	Coverage      Coverage            `json:"coverage"`
	Tools         Tools               `json:"tools"`
	Isolation     Isolation           `json:"isolation"`
	Validation    Validation          `json:"validation"`
	Findings      []normalize.Finding `json:"findings"`
	Policy        Policy              `json:"policy"`
	Errors        []Error             `json:"errors"`
}

// Run agrupa los campos volátiles.
type Run struct {
	ID           string         `json:"id"`
	StartedAt    string         `json:"started_at"`
	FinishedAt   string         `json:"finished_at"`
	DurationMS   int64          `json:"duration_ms"`
	CLIVersion   string         `json:"cli_version"`
	CLICommit    string         `json:"cli_commit"`
	Cancelled    bool           `json:"cancelled,omitempty"`
	Arguments    map[string]any `json:"arguments"`
	ConfigOrigin []ConfigOrigin `json:"config_origin"`
}

// ConfigOrigin registra el origen de un valor de configuración.
type ConfigOrigin struct {
	Key    string `json:"key"`
	Value  any    `json:"value"`
	Origin string `json:"origin"`
}

// Target describe lo analizado.
type Target struct {
	Root    string     `json:"root"`
	LocalID string     `json:"local_id"`
	VCS     VCS        `json:"vcs"`
	Units   []UnitInfo `json:"units"`
}

// VCS conserva el contexto de Git si está disponible.
type VCS struct {
	Available            bool   `json:"available"`
	Revision             string `json:"revision,omitempty"`
	Branch               string `json:"branch,omitempty"`
	Dirty                bool   `json:"dirty,omitempty"`
	Untracked            int    `json:"untracked,omitempty"`
	HeadChangedDuringRun bool   `json:"head_changed_during_run,omitempty"`
}

// UnitInfo es una unidad detectada.
type UnitInfo struct {
	ID        string               `json:"id"`
	Path      string               `json:"path"`
	Kind      string               `json:"kind"`
	Languages []discovery.Language `json:"languages"`
	Manifests []string             `json:"manifests,omitempty"`
}

// Coverage es la sección de honestidad de cobertura.
type Coverage struct {
	Partial     bool                `json:"partial"`
	Scope       Scope               `json:"scope"`
	Exclusions  []ExclusionReport   `json:"exclusions"`
	NotAnalyzed []NotAnalyzedReport `json:"not_analyzed"`
	Units       []UnitCoverage      `json:"units"`
	Limitations []string            `json:"limitations"`
}

// Scope delimita el universo analizado.
type Scope struct {
	Root    string   `json:"root"`
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// ExclusionReport conserva el origen de cada exclusión.
type ExclusionReport struct {
	Pattern   string   `json:"pattern"`
	Origin    string   `json:"origin"`
	Reason    string   `json:"reason,omitempty"`
	AppliedTo []string `json:"applied_to,omitempty"`
}

// NotAnalyzedReport enumera una unidad no analizada.
type NotAnalyzedReport struct {
	Unit     string   `json:"unit"`
	Path     string   `json:"path"`
	Reason   string   `json:"reason"`
	Patterns []string `json:"patterns,omitempty"`
}

// UnitCoverage es el estado por unidad.
type UnitCoverage struct {
	ID        string               `json:"id"`
	Path      string               `json:"path"`
	Languages []discovery.Language `json:"languages,omitempty"`
	Status    string               `json:"status"`
	Engines   []EngineState        `json:"engines"`
	Reason    string               `json:"reason,omitempty"`
}

// EngineState es el estado de un motor en una unidad.
type EngineState struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings,omitempty"`
}

// Tools agrupa los motores.
type Tools struct {
	Engines []EngineReport `json:"engines"`
}

// EngineReport describe un motor y su preparación.
type EngineReport struct {
	ID          string        `json:"id"`
	Version     string        `json:"version"`
	Status      string        `json:"status"`
	Mode        string        `json:"mode"`
	Isolation   string        `json:"isolation,omitempty"`
	DurationMS  int64         `json:"duration_ms,omitempty"`
	Path        string        `json:"path,omitempty"`
	Image       string        `json:"image,omitempty"`
	DB          *DBState      `json:"db,omitempty"`
	Rules       *RulesState   `json:"rules,omitempty"`
	Preparation []Preparation `json:"preparation,omitempty"`
	Units       []EngineState `json:"units"`
	Limitations []string      `json:"limitations,omitempty"`
}

// DBState registra la base usada.
type DBState struct {
	Source     string  `json:"source"`
	Status     string  `json:"status"`
	UpdatedAt  *string `json:"updated_at,omitempty"`
	AgeSeconds *int64  `json:"age_seconds,omitempty"`
	Schema     *int    `json:"schema,omitempty"`
	SHA256     *string `json:"sha256,omitempty"`
	Detail     string  `json:"detail,omitempty"`
}

// RulesState registra las reglas efectivas.
type RulesState struct {
	Source  string `json:"source"`
	Version string `json:"version,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Count   int    `json:"count,omitempty"`
}

// Preparation es una acción de preparación.
type Preparation struct {
	Action string `json:"action"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Isolation declara el nivel efectivo.
type Isolation struct {
	Level      string `json:"level"`
	VerifiedBy string `json:"verified_by"`
}

// Validation registra las recetas efectivas.
type Validation struct {
	Recipes    []Recipe     `json:"recipes"`
	Unresolved []Unresolved `json:"unresolved"`
}

// Recipe es una receta de tests o build confirmada por el usuario.
type Recipe struct {
	Unit    string `json:"unit"`
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Workdir string `json:"workdir"`
	Origin  string `json:"origin"`
}

// Unresolved es una unidad sin receta.
type Unresolved struct {
	Unit    string   `json:"unit"`
	Missing []string `json:"missing"`
}

// Policy es la evaluación efectiva.
type Policy struct {
	FailOn          string            `json:"fail_on"`
	Violated        bool              `json:"violated"`
	UnknownCounts   bool              `json:"unknown_counts"`
	Exceptions      []ExceptionReport `json:"exceptions"`
	SuppressedCount int               `json:"suppressed_count"`
}

// ExceptionReport es una excepción del archivo de política.
type ExceptionReport struct {
	Fingerprint string `json:"fingerprint"`
	Reason      string `json:"reason"`
	Owner       string `json:"owner"`
	Expires     string `json:"expires"`
	Effective   bool   `json:"effective"`
}

// Error es un error estructurado.
type Error struct {
	Code      string `json:"code"`
	Scope     string `json:"scope"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	Detail    string `json:"detail,omitempty"`
}

// LocalID calcula el identificador local estable de una ruta.
func LocalID(root string) string {
	sum := sha256.Sum256([]byte(root))
	return "local:" + hex.EncodeToString(sum[:])[:16]
}

// NewRun construye la sección volátil.
func NewRun(id string, started time.Time, duration time.Duration, args map[string]any) Run {
	end := started.Add(duration)
	return Run{
		ID:         id,
		StartedAt:  started.UTC().Format(time.RFC3339Nano),
		FinishedAt: end.UTC().Format(time.RFC3339Nano),
		DurationMS: duration.Milliseconds(),
		CLIVersion: version.Version,
		CLICommit:  version.Commit,
		Arguments:  args,
	}
}

// NewRunID genera un identificador de ejecución legible y único.
func NewRunID(now time.Time) string {
	return fmt.Sprintf("%s-%s", now.UTC().Format("20060102T150405Z"), randomHex(4))
}

func randomHex(n int) string {
	b := make([]byte, n)
	// crypto/rand nunca falla en la práctica; si fallara, el ID sigue siendo
	// único por el timestamp y el sufijo queda en cero.
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

// Normalize garantiza que las listas se serialicen como [] y no como null,
// ordena los hallazgos y valida la forma del documento.
func (d *Document) Normalize() {
	if d.SchemaVersion == "" {
		d.SchemaVersion = version.SchemaVersion
	}
	if d.Run.Arguments == nil {
		d.Run.Arguments = map[string]any{}
	}
	if d.Run.ConfigOrigin == nil {
		d.Run.ConfigOrigin = []ConfigOrigin{}
	}
	if d.Target.Units == nil {
		d.Target.Units = []UnitInfo{}
	}
	if d.Coverage.Scope.Include == nil {
		d.Coverage.Scope.Include = []string{}
	}
	if d.Coverage.Scope.Exclude == nil {
		d.Coverage.Scope.Exclude = []string{}
	}
	if d.Coverage.Exclusions == nil {
		d.Coverage.Exclusions = []ExclusionReport{}
	}
	if d.Coverage.NotAnalyzed == nil {
		d.Coverage.NotAnalyzed = []NotAnalyzedReport{}
	}
	if d.Coverage.Units == nil {
		d.Coverage.Units = []UnitCoverage{}
	}
	if d.Coverage.Limitations == nil {
		d.Coverage.Limitations = []string{}
	}
	if d.Tools.Engines == nil {
		d.Tools.Engines = []EngineReport{}
	}
	if d.Validation.Recipes == nil {
		d.Validation.Recipes = []Recipe{}
	}
	if d.Validation.Unresolved == nil {
		d.Validation.Unresolved = []Unresolved{}
	}
	if d.Findings == nil {
		d.Findings = []normalize.Finding{}
	}
	if d.Policy.Exceptions == nil {
		d.Policy.Exceptions = []ExceptionReport{}
	}
	if d.Errors == nil {
		d.Errors = []Error{}
	}
	for i := range d.Findings {
		if d.Findings[i].Policy.Status == "" {
			d.Findings[i].Policy.Status = "active"
		}
	}
	normalize.SortFindings(d.Findings)
	sort.SliceStable(d.Coverage.Exclusions, func(i, j int) bool {
		a, b := d.Coverage.Exclusions[i], d.Coverage.Exclusions[j]
		if a.Pattern == b.Pattern {
			return a.Origin < b.Origin
		}
		return a.Pattern < b.Pattern
	})
}

// MarshalJSON serializa el documento de forma determinista. Usa un alias para
// no llamarse a sí mismo a través de encoding/json.
func (d *Document) MarshalJSON() ([]byte, error) {
	d.Normalize()
	type documentAlias Document
	out, err := json.MarshalIndent((*documentAlias)(d), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
