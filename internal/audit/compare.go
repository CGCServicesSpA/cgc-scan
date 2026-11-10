package audit

import (
	"errors"
	"fmt"
	"sort"
)

// CompareSchemaVersion identifica el documento de comparación entre corridas.
const CompareSchemaVersion = "audit-compare-1.0.0"

// Clasificaciones de un hallazgo confirmado entre dos corridas.
const (
	// CompareNew: confirmado ahora y sin confirmación anterior.
	CompareNew = "new"
	// ComparePersistent: confirmado antes y ahora.
	ComparePersistent = "persistent"
	// CompareResolved: confirmado antes y evaluado como ausente o refutado en
	// la corrida actual, con evidencia de evaluación actual.
	CompareResolved = "resolved"
	// CompareNotEvaluated: confirmado antes, sin evidencia de evaluación
	// actual (corrida parcial, bloqueada o con el registro sin revalidar).
	CompareNotEvaluated = "not_evaluated"
)

// CompareVerdict archiva el veredicto observado en una corrida, con su
// relación de consolidación si la hubo.
type CompareVerdict struct {
	Verdict    string `json:"verdict"`
	MergedInto string `json:"merged_into,omitempty"`
}

// CompareEntry clasifica un hallazgo confirmado.
type CompareEntry struct {
	Fingerprint    string          `json:"fingerprint"`
	Classification string          `json:"classification"`
	Prior          *CompareVerdict `json:"prior,omitempty"`
	Current        *CompareVerdict `json:"current,omitempty"`
	Reason         string          `json:"reason,omitempty"`
}

// CompareRunRef identifica la corrida comparada.
type CompareRunRef struct {
	RunID   string `json:"run_id"`
	Profile string `json:"profile"`
	Status  string `json:"run_status"`
}

// Compare es el documento de comparación entre dos corridas.
type Compare struct {
	SchemaVersion string         `json:"schema_version"`
	Prior         CompareRunRef  `json:"prior"`
	Current       CompareRunRef  `json:"current"`
	Entries       []CompareEntry `json:"entries"`
	Summary       CompareSummary `json:"summary"`
}

// CompareSummary cuenta las clasificaciones.
type CompareSummary struct {
	Persistent   int `json:"persistent"`
	New          int `json:"new"`
	Resolved     int `json:"resolved"`
	NotEvaluated int `json:"not_evaluated"`
}

// CompareRuns compara dos corridas de auditoría. Solo lee: no modifica
// ninguna corrida. Declara resolución únicamente con evidencia de evaluación
// actual: el registro refutado en la corrida actual, o una corrida actual
// completa sin recurrencia. Corridas parciales, bloqueadas o con el registro
// marcado por cambio de fuente no producen falsos resolved.
func CompareRuns(prior, current *RunState) (*Compare, error) {
	if prior == nil || current == nil {
		return nil, errors.New("auditoría: las dos corridas son obligatorias")
	}
	if prior.Ledger.SchemaVersion != current.Ledger.SchemaVersion {
		return nil, fmt.Errorf("auditoría: versiones de contrato incompatibles: %q y %q",
			prior.Ledger.SchemaVersion, current.Ledger.SchemaVersion)
	}
	if prior.Ledger.Run.ID == current.Ledger.Run.ID {
		return nil, errors.New("auditoría: las dos corridas son la misma")
	}

	doc := &Compare{
		SchemaVersion: CompareSchemaVersion,
		Prior:         runRefOf(prior.Ledger),
		Current:       runRefOf(current.Ledger),
		Entries:       []CompareEntry{},
	}

	priorVerdicts := decidedVerdicts(prior)
	currentVerdicts := decidedVerdicts(current)

	// Fingerprints que la corrida actual decidió (con cualquier veredicto),
	// siguiendo las relaciones de consolidación.
	decidedNow := map[string]bool{}
	for _, cand := range current.Candidates.Items {
		if cand.State == CandidateDecided && cand.Final != nil {
			decidedNow[cand.Fingerprint] = true
			if cand.MergedInto != "" {
				decidedNow[cand.MergedInto] = true
			}
		}
	}
	// Confirmados previos marcados con cambio de fuente: sin evaluación
	// actual.
	stale := map[string]bool{}
	if current.Ledger.Prior != nil {
		for _, fp := range current.Ledger.Prior.StaleConfirmed {
			stale[fp] = true
		}
	}

	seen := map[string]bool{}
	add := func(fp string, prior *CompareVerdict, cur *CompareVerdict, classification, reason string) {
		if seen[fp] {
			return
		}
		seen[fp] = true
		doc.Entries = append(doc.Entries, CompareEntry{
			Fingerprint: fp, Classification: classification,
			Prior: prior, Current: cur, Reason: reason,
		})
	}

	for _, cand := range prior.Candidates.Items {
		if cand.State != CandidateDecided || cand.Final == nil || cand.Final.Verdict != VerdictConfirmed {
			continue
		}
		pv := &CompareVerdict{Verdict: cand.Final.Verdict, MergedInto: cand.MergedInto}
		if cur, ok := currentVerdicts[cand.Fingerprint]; ok {
			if cur.Verdict == VerdictConfirmed {
				add(cand.Fingerprint, pv, cur, ComparePersistent, "confirmado en ambas corridas")
			} else if cur.Verdict == VerdictRejected {
				add(cand.Fingerprint, pv, cur, CompareResolved, "refutado en la corrida actual")
			} else {
				add(cand.Fingerprint, pv, cur, CompareNotEvaluated, "pendiente de validación en la corrida actual")
			}
			continue
		}
		if stale[cand.Fingerprint] {
			add(cand.Fingerprint, pv, nil, CompareNotEvaluated, "la fuente cambió desde el registro; exige revalidación")
			continue
		}
		if current.Ledger.RunStatus == StatusComplete {
			add(cand.Fingerprint, pv, nil, CompareResolved, "la corrida actual es completa y el registro no recurre")
			continue
		}
		add(cand.Fingerprint, pv, nil, CompareNotEvaluated, "la corrida actual está "+current.Ledger.RunStatus+"; sin evidencia de evaluación")
	}

	for _, cand := range current.Candidates.Items {
		if cand.State != CandidateDecided || cand.Final == nil || cand.Final.Verdict != VerdictConfirmed {
			continue
		}
		if seen[cand.Fingerprint] {
			continue
		}
		cv := &CompareVerdict{Verdict: cand.Final.Verdict, MergedInto: cand.MergedInto}
		if pv, ok := priorVerdicts[cand.Fingerprint]; ok && pv.Verdict == VerdictConfirmed {
			add(cand.Fingerprint, pv, cv, ComparePersistent, "confirmado en ambas corridas")
			continue
		}
		add(cand.Fingerprint, nil, cv, CompareNew, "sin confirmación anterior")
	}

	sort.SliceStable(doc.Entries, func(i, j int) bool {
		return doc.Entries[i].Fingerprint < doc.Entries[j].Fingerprint
	})
	for _, e := range doc.Entries {
		switch e.Classification {
		case ComparePersistent:
			doc.Summary.Persistent++
		case CompareNew:
			doc.Summary.New++
		case CompareResolved:
			doc.Summary.Resolved++
		case CompareNotEvaluated:
			doc.Summary.NotEvaluated++
		}
	}
	return doc, nil
}

// decidedVerdicts indexa los veredictos con disposición final de una corrida,
// resolviendo las relaciones de consolidación hacia su registro.
func decidedVerdicts(st *RunState) map[string]*CompareVerdict {
	out := map[string]*CompareVerdict{}
	for _, cand := range st.Candidates.Items {
		if cand.State != CandidateDecided || cand.Final == nil {
			continue
		}
		v := &CompareVerdict{Verdict: cand.Final.Verdict, MergedInto: cand.MergedInto}
		out[cand.Fingerprint] = v
		if cand.MergedInto != "" {
			out[cand.MergedInto] = v
		}
	}
	return out
}

func runRefOf(l *Ledger) CompareRunRef {
	return CompareRunRef{RunID: l.Run.ID, Profile: l.Profile, Status: l.RunStatus}
}
