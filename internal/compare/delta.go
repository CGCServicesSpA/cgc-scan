package compare

import (
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// ReportDelta convierte el resultado de compare al tipo del contrato, para
// incluirlo en el reporte canónico y en el documento de agente.
func ReportDelta(res Result) *report.Delta {
	convert := func(entries []Entry) []report.DeltaEntry {
		out := make([]report.DeltaEntry, 0, len(entries))
		for _, e := range entries {
			out = append(out, report.DeltaEntry{
				Fingerprint: e.Fingerprint, Kind: e.Kind, Title: e.Title,
				Severity: e.Severity, Path: e.Path, Engine: e.Engine,
				Package: e.Package, FixedVersion: e.FixedVersion, Group: e.Group,
			})
		}
		return out
	}
	return &report.Delta{
		BaselineRun: res.Previous, CurrentRun: res.Current,
		CoverageComparable: res.CoverageComparable, Reason: res.Reason,
		New: convert(res.New), Persistent: convert(res.Persistent),
		Resolved: convert(res.Resolved), NotEvaluated: convert(res.NotEvaluated),
	}
}
