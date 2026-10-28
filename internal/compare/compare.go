// Package compare clasifica hallazgos entre dos reportes: nuevo, persistente,
// resuelto y no evaluado (RF-10, CA-09).
package compare

import (
	"sort"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// Entry es un hallazgo comparado.
type Entry struct {
	Fingerprint  string             `json:"fingerprint"`
	Kind         normalize.Kind     `json:"kind"`
	Title        string             `json:"title"`
	Severity     normalize.Severity `json:"severity"`
	Path         string             `json:"path,omitempty"`
	Engine       string             `json:"engine,omitempty"`
	Package      string             `json:"package,omitempty"`
	FixedVersion string             `json:"fixed_version,omitempty"`
}

// Result es el contrato de `compare`.
type Result struct {
	Previous           string  `json:"previous"`
	Current            string  `json:"current"`
	CoverageComparable bool    `json:"coverage_comparable"`
	Reason             string  `json:"reason,omitempty"`
	New                []Entry `json:"new"`
	Persistent         []Entry `json:"persistent"`
	Resolved           []Entry `json:"resolved"`
	NotEvaluated       []Entry `json:"not_evaluated"`
}

// Compare clasifica los hallazgos. Un hallazgo ausente solo se declara resuelto
// si el escaneo actual fue completo y comparable; en un escaneo parcial o con
// errores queda como no evaluado.
func Compare(previous, current *report.Document) Result {
	res := Result{
		Previous:           previous.Run.ID,
		Current:            current.Run.ID,
		CoverageComparable: len(current.Errors) == 0 && !current.Coverage.Partial,
	}
	if !res.CoverageComparable {
		res.Reason = "el escaneo actual es parcial o tiene errores; los hallazgos ausentes no se pueden declarar resueltos"
	}
	prev := index(previous.Findings)
	cur := index(current.Findings)
	for fp, f := range cur {
		if _, ok := prev[fp]; ok {
			res.Persistent = append(res.Persistent, entryOf(f))
		} else {
			res.New = append(res.New, entryOf(f))
		}
	}
	for fp, f := range prev {
		if _, ok := cur[fp]; ok {
			continue
		}
		if res.CoverageComparable {
			res.Resolved = append(res.Resolved, entryOf(f))
		} else {
			res.NotEvaluated = append(res.NotEvaluated, entryOf(f))
		}
	}
	sortEntries(res.New)
	sortEntries(res.Persistent)
	sortEntries(res.Resolved)
	sortEntries(res.NotEvaluated)
	if res.New == nil {
		res.New = []Entry{}
	}
	if res.Persistent == nil {
		res.Persistent = []Entry{}
	}
	if res.Resolved == nil {
		res.Resolved = []Entry{}
	}
	if res.NotEvaluated == nil {
		res.NotEvaluated = []Entry{}
	}
	return res
}

func index(findings []normalize.Finding) map[string]normalize.Finding {
	out := make(map[string]normalize.Finding, len(findings))
	for _, f := range findings {
		out[f.Fingerprint] = f
	}
	return out
}

func entryOf(f normalize.Finding) Entry {
	e := Entry{
		Fingerprint: f.Fingerprint,
		Kind:        f.Kind,
		Title:       f.Title,
		Severity:    f.Severity.Normalized,
	}
	if len(f.Locations) > 0 {
		e.Path = f.Locations[0].Path
	}
	if len(f.Sources) > 0 {
		e.Engine = f.Sources[0].Engine
	}
	if f.Package != nil {
		e.Package = f.Package.Name + " " + f.Package.Version
		if f.Package.FixedVersion != nil {
			e.FixedVersion = *f.Package.FixedVersion
		}
	}
	return e
}

func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Severity.Rank() != entries[j].Severity.Rank() {
			return entries[i].Severity.Rank() > entries[j].Severity.Rank()
		}
		return entries[i].Fingerprint < entries[j].Fingerprint
	})
}
