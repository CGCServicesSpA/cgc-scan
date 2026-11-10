package remediation

import (
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
)

// Score calcula una prioridad determinista de 0 a 100 y devuelve sus factores
// visibles. Los datos ausentes no suman ni restan: nunca se inventan.
func Score(f normalize.Finding) (int, []string) {
	score := 20
	factors := make([]string, 0, 8)
	switch f.Severity.Normalized {
	case normalize.SeverityCritical:
		score, factors = 70, append(factors, "critical")
	case normalize.SeverityHigh:
		score, factors = 58, append(factors, "high")
	case normalize.SeverityMedium:
		score, factors = 45, append(factors, "medium")
	case normalize.SeverityLow:
		score, factors = 30, append(factors, "low")
	case normalize.SeverityInformational:
		score, factors = 15, append(factors, "info")
	default:
		score, factors = 20, append(factors, "unknown")
	}
	if f.Priority != nil {
		if f.Priority.KEV != nil && *f.Priority.KEV {
			score += 15
			factors = append(factors, "kev")
		}
		if f.Priority.EPSS != nil {
			switch {
			case *f.Priority.EPSS >= 0.5:
				score += 10
				factors = append(factors, "epss_high")
			case *f.Priority.EPSS >= 0.1:
				score += 5
				factors = append(factors, "epss_medium")
			}
		}
		if f.Priority.Reachable != nil {
			if *f.Priority.Reachable {
				score += 10
				factors = append(factors, "reachable")
			} else {
				score -= 6
				factors = append(factors, "not_reachable")
			}
		}
	}
	if f.Package != nil && f.Package.FixedVersion != nil && *f.Package.FixedVersion != "" {
		score += 6
		factors = append(factors, "fix_available")
	}
	if f.Package != nil && f.Package.Direct != nil {
		if *f.Package.Direct {
			score += 5
			factors = append(factors, "direct")
		} else {
			score -= 3
			factors = append(factors, "transitive")
		}
	}
	if ctx := pathContext(f); ctx != "" {
		score -= 10
		factors = append(factors, ctx)
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, factors
}

// ApplyPriority calcula y asigna score, rank y factors a todos los hallazgos.
func ApplyPriority(findings []normalize.Finding) {
	for i := range findings {
		score, factors := Score(findings[i])
		if findings[i].Priority == nil {
			findings[i].Priority = &normalize.Priority{}
		}
		s := score
		fs := factors
		findings[i].Priority.Score = &s
		findings[i].Priority.Factors = fs
	}
	order := make([]int, len(findings))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := findings[order[a]], findings[order[b]]
		sx, sy := 0, 0
		if x.Priority != nil && x.Priority.Score != nil {
			sx = *x.Priority.Score
		}
		if y.Priority != nil && y.Priority.Score != nil {
			sy = *y.Priority.Score
		}
		if sx != sy {
			return sx > sy
		}
		if x.Severity.Normalized.Rank() != y.Severity.Normalized.Rank() {
			return x.Severity.Normalized.Rank() > y.Severity.Normalized.Rank()
		}
		return x.Fingerprint < y.Fingerprint
	})
	for rank, idx := range order {
		r := rank + 1
		findings[idx].Priority.Rank = &r
	}
}

func pathContext(f normalize.Finding) string {
	for _, loc := range f.Locations {
		p := strings.ToLower(strings.ReplaceAll(loc.Path, "\\", "/"))
		for _, seg := range strings.Split(p, "/") {
			switch seg {
			case "test", "tests", "__tests__", "spec", "specs":
				return "test_path"
			case "fixture", "fixtures":
				return "fixture_path"
			case "example", "examples":
				return "example_path"
			}
		}
	}
	return ""
}
