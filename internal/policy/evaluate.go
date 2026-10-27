package policy

import (
	"sort"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
)

// Exception es una excepción declarada en la política del proyecto.
type Exception struct {
	Fingerprint string
	Reason      string
	Owner       string
	Expires     string // fecha UTC, formato YYYY-MM-DD
	Effective   bool
}

// Evaluation es el resultado de aplicar el umbral y las excepciones.
type Evaluation struct {
	FailOn          normalize.Severity
	Violated        bool
	UnknownCounts   bool
	Suppressed      []normalize.Finding
	Active          []normalize.Finding
	SuppressedCount int
}

// Evaluate aplica el umbral y las excepciones. Un hallazgo suprimido se
// conserva con su motivo. `info` nunca bloquea por sí sola; `unknown` solo
// cuenta contra el umbral si unknownCounts es verdadero.
func Evaluate(findings []normalize.Finding, failOn normalize.Severity, unknownCounts bool, exceptions []Exception) Evaluation {
	active := make([]Exception, 0, len(exceptions))
	byFingerprint := make(map[string]Exception, len(exceptions))
	for _, e := range exceptions {
		if e.Effective {
			byFingerprint[e.Fingerprint] = e
			active = append(active, e)
		}
	}

	out := Evaluation{FailOn: failOn, UnknownCounts: unknownCounts}
	for i := range findings {
		f := &findings[i]
		if ex, ok := byFingerprint[f.Fingerprint]; ok {
			f.Policy = normalize.FindingPolicy{
				Status:               "suppressed",
				SuppressedReason:     ex.Reason,
				ExceptionFingerprint: ex.Fingerprint,
			}
			out.Suppressed = append(out.Suppressed, *f)
			out.SuppressedCount++
			continue
		}
		f.Policy = normalize.FindingPolicy{Status: "active"}
		out.Active = append(out.Active, *f)
		if blocks(f.Severity.Normalized, failOn, unknownCounts) {
			out.Violated = true
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Fingerprint < active[j].Fingerprint })
	return out
}

func blocks(severity, failOn normalize.Severity, unknownCounts bool) bool {
	if severity == normalize.SeverityInformational {
		return false // no bloquea por sí sola
	}
	if severity == normalize.SeverityUnknown {
		return unknownCounts
	}
	if !failOn.Valid() || failOn == normalize.SeverityUnknown {
		// Un umbral sin severidad concreta no puede compararse: se comporta
		// como high, el valor por defecto.
		failOn = normalize.SeverityHigh
	}
	if failOn == normalize.SeverityInformational {
		failOn = normalize.SeverityLow
	}
	return severity.Rank() >= failOn.Rank()
}
