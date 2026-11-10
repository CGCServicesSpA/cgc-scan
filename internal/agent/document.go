// Package agent construye el documento compacto de una sola pasada para
// agentes: resumen, grupos, próximas acciones, delta y bloqueos.
package agent

import (
	"encoding/json"
	"sort"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

// Document es el contrato `agent-1.0.0`. No incluye descripciones,
// referencias ni evidencia: esos datos se piden con `cgc-scan explain`.
type Document struct {
	SchemaVersion     string                    `json:"schema_version"`
	Run               Run                       `json:"run"`
	Target            Target                    `json:"target"`
	Summary           Summary                   `json:"summary"`
	RemediationGroups []report.RemediationGroup `json:"remediation_groups"`
	NextActions       []report.NextAction       `json:"next_actions"`
	Delta             *report.Delta             `json:"delta,omitempty"`
	Blocked           []Blocked                 `json:"blocked"`
	ReportPath        string                    `json:"report_path"`
	Errors            []report.Error            `json:"errors"`
}

// Run identifica la ejecución.
type Run struct {
	ID              string `json:"id"`
	FinishedAt      string `json:"finished_at"`
	DurationMS      int64  `json:"duration_ms"`
	CLIVersion      string `json:"cli_version"`
	BaselineCreated bool   `json:"baseline_created,omitempty"`
}

// Target identifica el proyecto analizado.
type Target struct {
	Root    string `json:"root"`
	LocalID string `json:"local_id"`
}

// Summary es el estado que el agente necesita antes de actuar.
type Summary struct {
	Status         string          `json:"status"`
	ExitCode       int             `json:"exit_code"`
	Coverage       SummaryCoverage `json:"coverage"`
	Counts         SummaryCounts   `json:"counts"`
	GroupsTotal    int             `json:"groups_total"`
	GroupsShown    int             `json:"groups_shown"`
	GroupsFiltered int             `json:"groups_filtered,omitempty"`
	Truncated      bool            `json:"truncated"`
	Filter         *ViewFilter     `json:"filter,omitempty"`
}

// ViewFilter declara un filtro de vista aplicado solo a la salida compacta.
type ViewFilter struct {
	MinSeverity normalize.Severity `json:"min_severity"`
}

// SummaryCoverage declara la honestidad de la cobertura.
type SummaryCoverage struct {
	Partial bool `json:"partial"`
	Units   int  `json:"units"`
	Errors  int  `json:"errors"`
}

// SummaryCounts resume hallazgos y delta.
type SummaryCounts struct {
	Findings     int `json:"findings"`
	Suppressed   int `json:"suppressed"`
	Groups       int `json:"groups"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Info         int `json:"info"`
	Unknown      int `json:"unknown"`
	New          int `json:"new"`
	Persistent   int `json:"persistent"`
	Resolved     int `json:"resolved"`
	NotEvaluated int `json:"not_evaluated"`
}

// Blocked explica una validación o motor bloqueado.
type Blocked struct {
	Kind   string `json:"kind"`
	Unit   string `json:"unit,omitempty"`
	Engine string `json:"engine,omitempty"`
	Reason string `json:"reason"`
}

// Options ajusta la construcción.
type Options struct {
	ExitCode        int
	ReportPath      string
	BaselineCreated bool
	MaxGroups       int
	// MinSeverity filtra solo la vista del agente; nunca el reporte canónico.
	MinSeverity normalize.Severity
}

// Build convierte el reporte canónico en el documento compacto. No inventa
// grupos ni acciones: usa los ya calculados en el reporte.
func Build(doc *report.Document, opts Options) Document {
	d := Document{
		SchemaVersion: version.AgentSchemaVersion,
		Run: Run{
			ID: doc.Run.ID, FinishedAt: doc.Run.FinishedAt, DurationMS: doc.Run.DurationMS,
			CLIVersion: doc.Run.CLIVersion, BaselineCreated: opts.BaselineCreated,
		},
		Target:            Target{Root: doc.Target.Root, LocalID: doc.Target.LocalID},
		RemediationGroups: append([]report.RemediationGroup{}, doc.RemediationGroups...),
		NextActions:       append([]report.NextAction{}, doc.NextActions...),
		Delta:             doc.Delta,
		Blocked:           blockedOf(doc),
		ReportPath:        opts.ReportPath,
		Errors:            append([]report.Error{}, doc.Errors...),
	}
	d.Summary = Summary{
		ExitCode: opts.ExitCode,
		Coverage: SummaryCoverage{
			Partial: doc.Coverage.Partial, Units: len(doc.Coverage.Units), Errors: len(doc.Errors),
		},
		GroupsTotal: len(doc.RemediationGroups),
	}
	for _, f := range doc.Findings {
		if f.Policy.Status == "suppressed" {
			d.Summary.Counts.Suppressed++
			continue
		}
		d.Summary.Counts.Findings++
		switch f.Severity.Normalized {
		case normalize.SeverityCritical:
			d.Summary.Counts.Critical++
		case normalize.SeverityHigh:
			d.Summary.Counts.High++
		case normalize.SeverityMedium:
			d.Summary.Counts.Medium++
		case normalize.SeverityLow:
			d.Summary.Counts.Low++
		case normalize.SeverityInformational:
			d.Summary.Counts.Info++
		default:
			d.Summary.Counts.Unknown++
		}
	}
	d.Summary.Counts.Groups = len(doc.RemediationGroups)
	if doc.Delta != nil {
		d.Summary.Counts.New = len(doc.Delta.New)
		d.Summary.Counts.Persistent = len(doc.Delta.Persistent)
		d.Summary.Counts.Resolved = len(doc.Delta.Resolved)
		d.Summary.Counts.NotEvaluated = len(doc.Delta.NotEvaluated)
	}
	d.Summary.Status = statusOf(d)

	if opts.MinSeverity != "" {
		threshold := opts.MinSeverity.Rank()
		shown := make([]report.RemediationGroup, 0, len(d.RemediationGroups))
		allowed := map[string]bool{}
		for _, g := range d.RemediationGroups {
			if g.MaxSeverity.Rank() < threshold {
				continue
			}
			shown = append(shown, g)
			allowed[g.ID] = true
		}
		d.Summary.Filter = &ViewFilter{MinSeverity: opts.MinSeverity}
		if len(shown) != len(d.RemediationGroups) {
			actions := make([]report.NextAction, 0, len(d.NextActions))
			for _, a := range d.NextActions {
				if a.Group == "" || allowed[a.Group] {
					actions = append(actions, a)
				}
			}
			d.NextActions = actions
			d.Summary.GroupsFiltered = len(d.RemediationGroups) - len(shown)
			d.RemediationGroups = shown
		}
	}

	if opts.MaxGroups > 0 && len(d.RemediationGroups) > opts.MaxGroups {
		shown := d.RemediationGroups[:opts.MaxGroups]
		allowed := map[string]bool{}
		for _, g := range shown {
			allowed[g.ID] = true
		}
		actions := make([]report.NextAction, 0, len(d.NextActions))
		for _, a := range d.NextActions {
			if a.Group == "" || allowed[a.Group] {
				actions = append(actions, a)
			}
		}
		d.RemediationGroups = shown
		d.NextActions = actions
		d.Summary.Truncated = true
	}
	d.Summary.GroupsShown = len(d.RemediationGroups)
	if d.Blocked == nil {
		d.Blocked = []Blocked{}
	}
	if d.RemediationGroups == nil {
		d.RemediationGroups = []report.RemediationGroup{}
	}
	if d.NextActions == nil {
		d.NextActions = []report.NextAction{}
	}
	if d.Errors == nil {
		d.Errors = []report.Error{}
	}
	return d
}

// JSON serializa el documento de forma estable.
func (d Document) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func statusOf(d Document) string {
	switch {
	case d.Run.ID == "":
		return "failed"
	case d.Summary.ExitCode == 3:
		return "failed"
	case d.Summary.Counts.Findings > 0:
		return "findings"
	case len(d.Blocked) > 0:
		return "blocked"
	case d.Summary.Coverage.Partial:
		return "partial"
	default:
		return "clean"
	}
}

func blockedOf(doc *report.Document) []Blocked {
	out := make([]Blocked, 0)
	for _, u := range doc.Validation.Unresolved {
		out = append(out, Blocked{
			Kind: "missing_recipes", Unit: u.Unit,
			Reason: "faltan recetas: " + join(u.Missing),
		})
	}
	for _, e := range doc.Errors {
		kind := e.Code
		if kind == "requirement_missing" {
			kind = "missing_toolchain"
		}
		b := Blocked{Kind: kind, Reason: e.Message}
		if i := indexByte(e.Scope, ':'); i >= 0 {
			b.Engine, b.Unit = e.Scope[:i], e.Scope[i+1:]
		}
		out = append(out, b)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Unit != out[j].Unit {
			return out[i].Unit < out[j].Unit
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

func join(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
