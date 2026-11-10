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
	SchemaVersion     string              `json:"schema_version"`
	Run               Run                 `json:"run"`
	Target            Target              `json:"target"`
	Coverage          Coverage            `json:"coverage"`
	Tools             Tools               `json:"tools"`
	Isolation         Isolation           `json:"isolation"`
	Validation        Validation          `json:"validation"`
	Findings          []normalize.Finding `json:"findings"`
	RemediationGroups []RemediationGroup  `json:"remediation_groups"`
	NextActions       []NextAction        `json:"next_actions"`
	Delta             *Delta              `json:"delta,omitempty"`
	Policy            Policy              `json:"policy"`
	Errors            []Error             `json:"errors"`
}

// RemediationGroup agrupa hallazgos que se corrigen con una sola acción.
// El identificador es estable y se usa en `verify`.
type RemediationGroup struct {
	ID            string             `json:"id"`
	Kind          string             `json:"kind"`
	Unit          string             `json:"unit"`
	Package       *GroupPackage      `json:"package,omitempty"`
	File          string             `json:"file,omitempty"`
	Rule          string             `json:"rule,omitempty"`
	Fixes         []string           `json:"fixes"`
	Locations     int                `json:"locations,omitempty"`
	MaxSeverity   normalize.Severity `json:"max_severity"`
	PriorityScore int                `json:"priority_score"`
	BreakingRisk  string             `json:"breaking_risk"`
	Direct        *bool              `json:"direct,omitempty"`
	Commands      GroupCommands      `json:"commands"`
	Verification  GroupVerification  `json:"verification"`
	Note          string             `json:"note,omitempty"`
}

// GroupPackage describe el componente y el salto de versión propuesto.
type GroupPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// GroupCommands son sugerencias de aplicación. La CLI nunca las ejecuta.
type GroupCommands struct {
	Apply    string `json:"apply,omitempty"`
	Override string `json:"override,omitempty"`
	Origin   string `json:"origin"`
}

// GroupVerification dice cómo comprobar que el grupo quedó corregido.
type GroupVerification struct {
	Status  string                         `json:"status"`
	Recipes []normalize.VerificationRecipe `json:"recipes"`
	Missing []string                       `json:"missing"`
	Verify  string                         `json:"verify"`
	Note    string                         `json:"note,omitempty"`
}

// NextAction es un paso ordenado y determinista para el agente.
type NextAction struct {
	Action       string `json:"action"`
	Unit         string `json:"unit,omitempty"`
	Group        string `json:"group,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	Tool         string `json:"tool,omitempty"`
	Command      string `json:"command,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Fixes        int    `json:"fixes,omitempty"`
	UserRequired bool   `json:"user_required,omitempty"`
}

// Delta clasifica los hallazgos frente a la línea base.
type Delta struct {
	BaselineRun        string       `json:"baseline_run,omitempty"`
	CurrentRun         string       `json:"current_run,omitempty"`
	CoverageComparable bool         `json:"coverage_comparable"`
	Reason             string       `json:"reason,omitempty"`
	New                []DeltaEntry `json:"new"`
	Persistent         []DeltaEntry `json:"persistent"`
	Resolved           []DeltaEntry `json:"resolved"`
	NotEvaluated       []DeltaEntry `json:"not_evaluated"`
}

// DeltaEntry es un hallazgo dentro del delta.
type DeltaEntry struct {
	Fingerprint  string             `json:"fingerprint"`
	Kind         normalize.Kind     `json:"kind"`
	Title        string             `json:"title"`
	Severity     normalize.Severity `json:"severity"`
	Path         string             `json:"path,omitempty"`
	Engine       string             `json:"engine,omitempty"`
	Package      string             `json:"package,omitempty"`
	FixedVersion string             `json:"fixed_version,omitempty"`
	Group        string             `json:"group,omitempty"`
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
	Cache    string `json:"cache,omitempty"`
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
	Cache       string        `json:"cache,omitempty"`
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
	for i := range d.Target.Units {
		if d.Target.Units[i].Languages == nil {
			d.Target.Units[i].Languages = []discovery.Language{}
		}
	}
	for i := range d.Coverage.Units {
		if d.Coverage.Units[i].Languages == nil {
			d.Coverage.Units[i].Languages = []discovery.Language{}
		}
	}
	for i := range d.Tools.Engines {
		if d.Tools.Engines[i].Units == nil {
			d.Tools.Engines[i].Units = []EngineState{}
		}
	}
	if d.Findings == nil {
		d.Findings = []normalize.Finding{}
	}
	if d.RemediationGroups == nil {
		d.RemediationGroups = []RemediationGroup{}
	}
	if d.NextActions == nil {
		d.NextActions = []NextAction{}
	}
	for i := range d.RemediationGroups {
		if d.RemediationGroups[i].Fixes == nil {
			d.RemediationGroups[i].Fixes = []string{}
		}
		if d.RemediationGroups[i].Verification.Recipes == nil {
			d.RemediationGroups[i].Verification.Recipes = []normalize.VerificationRecipe{}
		}
		if d.RemediationGroups[i].Verification.Missing == nil {
			d.RemediationGroups[i].Verification.Missing = []string{}
		}
	}
	if d.Delta != nil {
		if d.Delta.New == nil {
			d.Delta.New = []DeltaEntry{}
		}
		if d.Delta.Persistent == nil {
			d.Delta.Persistent = []DeltaEntry{}
		}
		if d.Delta.Resolved == nil {
			d.Delta.Resolved = []DeltaEntry{}
		}
		if d.Delta.NotEvaluated == nil {
			d.Delta.NotEvaluated = []DeltaEntry{}
		}
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
