package compare

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSON serializa el resultado.
func (r Result) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Text renderiza el resultado para terminal.
func (r Result) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Comparación: %s -> %s\n", r.Previous, r.Current)
	if !r.CoverageComparable {
		fmt.Fprintf(&b, "Cobertura no comparable: %s\n", r.Reason)
	}
	fmt.Fprintf(&b, "Nuevos: %d\n", len(r.New))
	fmt.Fprintf(&b, "Persistentes: %d\n", len(r.Persistent))
	fmt.Fprintf(&b, "Resueltos: %d\n", len(r.Resolved))
	fmt.Fprintf(&b, "No evaluados: %d\n", len(r.NotEvaluated))
	show := func(name string, entries []Entry) {
		if len(entries) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", name)
		for _, e := range entries {
			line := fmt.Sprintf("  [%s] %s - %s", e.Severity, e.Title, e.Path)
			if e.FixedVersion != "" {
				line += fmt.Sprintf(" (corregido en %s)", e.FixedVersion)
			}
			fmt.Fprintln(&b, line)
		}
	}
	show("Nuevos", r.New)
	show("Persistentes", r.Persistent)
	show("Resueltos", r.Resolved)
	show("No evaluados", r.NotEvaluated)
	return b.String()
}
