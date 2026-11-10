package audit

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

// ImportSchemaVersion identifica el resultado de una importación de leads.
const ImportSchemaVersion = "audit-import-1.0.0"

// ImportedLead archiva el hallazgo original de un motor separado del veredicto
// de auditoría: la severidad y prioridad del motor nunca se convierten en
// severidad auditada.
type ImportedLead struct {
	Fingerprint string            `json:"fingerprint"`
	Unit        string            `json:"unit"`
	Engine      string            `json:"engine"`
	Original    normalize.Finding `json:"original"`
}

// ImportOutcome resume lo que aplicó una importación.
type ImportOutcome struct {
	SchemaVersion string   `json:"schema_version"`
	AddedUnits    []string `json:"added_units"`
	Proposed      []string `json:"proposed_fingerprints"`
	Skipped       []string `json:"skipped_fingerprints"`
	Notes         []string `json:"notes"`
}

// ImportLeads mapea los hallazgos de un reporte de escaneo a leads pendientes
// de caza: unidades planificadas dedicadas y, únicamente cuando el contrato
// del veredicto se satisface, un candidato needs_validation.
//
// Ningún hallazgo importado aparece automáticamente como confirmado: el
// veredicto de un hallazgo del motor es una afirmación del motor, no una
// confirmación auditada, y su severidad no se convierte en severidad
// auditada. Importar dos veces produce el mismo trabajo pendiente.
func ImportLeads(l *Ledger, c *Candidates, doc *report.Document) (*ImportOutcome, []ImportedLead, error) {
	if l == nil || c == nil || doc == nil {
		return nil, nil, errors.New("auditoría: ledger, candidatos y reporte son obligatorios")
	}
	if doc.SchemaVersion != version.SchemaVersion {
		return nil, nil, fmt.Errorf("auditoría: reporte con esquema %q, se esperaba %q", doc.SchemaVersion, version.SchemaVersion)
	}
	if l.RunStatus != StatusInProgress {
		return nil, nil, fmt.Errorf("auditoría: la corrida está %s y no acepta importaciones", l.RunStatus)
	}

	out := &ImportOutcome{
		SchemaVersion: ImportSchemaVersion,
		AddedUnits:    []string{},
		Proposed:      []string{},
		Skipped:       []string{},
		Notes:         []string{},
	}
	leads := make([]ImportedLead, 0, len(doc.Findings))
	seenUnits := map[string]bool{}
	for _, u := range l.Units {
		seenUnits[u.CoverageID] = true
	}
	seenCandidates := map[string]bool{}
	for _, cand := range c.Items {
		seenCandidates[cand.Fingerprint] = true
	}

	for i := range doc.Findings {
		f := &doc.Findings[i]
		fp := f.Fingerprint
		if fp == "" || seenCandidates[fp] {
			out.Skipped = append(out.Skipped, fp)
			continue
		}
		if f.Policy.Status == "suppressed" {
			out.Skipped = append(out.Skipped, fp)
			out.Notes = append(out.Notes, "hallazgo suprimido por la política del proyecto: "+fp)
			continue
		}

		id := leadCoverageID(f)
		if !seenUnits[id] {
			unit, err := leadUnit(f)
			if err != nil {
				out.Skipped = append(out.Skipped, fp)
				out.Notes = append(out.Notes, fmt.Sprintf("hallazgo %s sin unidad utilizable: %v", fp, err))
				continue
			}
			seenUnits[id] = true
			l.Units = append(l.Units, unit)
			out.AddedUnits = append(out.AddedUnits, id)
		}

		// El veredicto needs_validation se emite únicamente cuando su
		// contrato se satisface: bloqueos del motor y plan de validación.
		if record, rerr := needsValidationRecord(f); rerr == nil {
			if err := validateRecord(*record); err != nil {
				out.Notes = append(out.Notes, fmt.Sprintf("hallazgo %s queda como lead sin veredicto: su registro no cumple el contrato del veredicto", fp))
			} else {
				seenCandidates[fp] = true
				c.Items = append(c.Items, Candidate{
					Fingerprint: fp,
					Unit:        id,
					HunterAgent: "import",
					Proposed:    *record,
					State:       CandidatePending,
					Attempts:    []VerificationAttempt{},
				})
				if u := l.UnitByID(id); u != nil {
					u.Candidates = appendUnique(u.Candidates, fp)
				}
				out.Proposed = append(out.Proposed, fp)
			}
		}
		leads = append(leads, ImportedLead{
			Fingerprint: fp,
			Unit:        id,
			Engine:      engineOf(f),
			Original:    *f,
		})
	}
	sort.Strings(out.Skipped)
	c.Normalize()
	l.Recompute()
	return out, leads, nil
}

// leadCoverageID es el identificador de la unidad lead de un hallazgo
// importado: estable y deduplicable entre importaciones.
func leadCoverageID(f *normalize.Finding) string {
	return "import/" + slugID(leadScope(f)) + "/" + slugID(f.Fingerprint)
}

// leadScope es el subsistema del lead: la unidad de verificación del motor o,
// en su defecto, el motor que lo emitió.
func leadScope(f *normalize.Finding) string {
	if f.Verification != nil && strings.TrimSpace(f.Verification.Unit) != "" {
		return f.Verification.Unit
	}
	return engineOf(f)
}

func engineOf(f *normalize.Finding) string {
	if len(f.Sources) > 0 && strings.TrimSpace(f.Sources[0].Engine) != "" {
		return f.Sources[0].Engine
	}
	return "desconocido"
}

// leadUnit construye la unidad planificada de un lead importado.
func leadUnit(f *normalize.Finding) (Unit, error) {
	starts := []string{}
	for _, loc := range f.Locations {
		if ValidRepoPath(loc.Path) {
			starts = appendUnique(starts, loc.Path)
		}
	}
	if len(starts) == 0 {
		starts = []string{"."}
	}
	unit := newUnit(leadCoverageID(f), slugID(leadScope(f)), "import", "engine-lead", leadAttackClass(f), starts)
	unit.Reason = ""
	return unit, nil
}

// leadAttackClass es la clase de ataque del lead: la categoría del hallazgo
// del motor, como clasificación del lead y no como clase auditada.
func leadAttackClass(f *normalize.Finding) string {
	return string(f.Kind)
}

// needsValidationRecord construye el registro needs_validation del hallazgo
// importado. Solo se emite cuando su contrato se satisface: bloqueos reales
// del motor (verification.missing) y un plan de validación (rescan).
func needsValidationRecord(f *normalize.Finding) (*Record, error) {
	v := f.Verification
	if v == nil || len(v.Missing) == 0 || strings.TrimSpace(v.Rescan) == "" {
		return nil, errors.New("el hallazgo importado no satisface el contrato del veredicto")
	}
	record := &Record{
		Verdict:          VerdictNeedsValidation,
		Fingerprint:      f.Fingerprint,
		Title:            f.Title,
		Description:      descriptionsOf(f),
		ClaimedRootCause: claimedOf(f),
		Blockers:         nonNil(v.Missing),
		ValidationPlan:   &ValidationPlan{Local: v.Rescan},
	}
	if loc := firstLocation(f); loc != nil {
		record.Trace = []TraceStep{{
			Kind:        "sink",
			File:        loc.Path,
			Line:        lineOf(loc),
			Scope:       engineOf(f),
			Description: "ubicación reportada por el motor",
		}}
		record.Evidence = []Evidence{{
			File:        loc.Path,
			Line:        lineOf(loc),
			Description: "ubicación reportada por el motor; el motor no ejecutó código del proyecto",
		}}
	}
	return record, nil
}

func descriptionsOf(f *normalize.Finding) string {
	parts := make([]string, 0, len(f.Descriptions))
	for _, d := range f.Descriptions {
		parts = appendUnique(parts, strings.TrimSpace(d.Text))
	}
	return strings.Join(parts, " ")
}

// claimedOf enmarca la afirmación del motor como hipótesis: es una claim, no
// una causa raíz confirmada.
func claimedOf(f *normalize.Finding) string {
	return "afirmación del motor " + engineOf(f) + ": " + f.Title
}

func firstLocation(f *normalize.Finding) *normalize.Location {
	for i := range f.Locations {
		if ValidRepoPath(f.Locations[i].Path) {
			return &f.Locations[i]
		}
	}
	return nil
}

func lineOf(loc *normalize.Location) int {
	if loc.StartLine != nil && *loc.StartLine >= 1 {
		return *loc.StartLine
	}
	return 1
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
