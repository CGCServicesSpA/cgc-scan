package normalize

import (
	"sort"
	"strings"
)

// Correlate fusiona hallazgos duplicados conservando todas las fuentes y las
// diferencias de severidad (RF-06, design §9.2).
//
//   - Dependencias: mismo componente (ecosistema, nombre, versión) y al menos
//     un alias de advisory en común.
//   - Código: misma clase de debilidad (CWE o regla), ruta y contexto.
//   - Configuración: misma regla y ruta.
//
// Nunca se fusiona por título ni por número de línea.
func Correlate(findings []Finding) []Finding {
	if len(findings) < 2 {
		return findings
	}
	parent := make([]int, len(findings))
	for i := range parent {
		parent[i] = i
	}
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[rb] = ra
		}
	}

	seen := map[string]int{}
	for i := range findings {
		for _, key := range correlationKeys(findings[i]) {
			if j, ok := seen[key]; ok {
				union(i, j)
			} else {
				seen[key] = i
			}
		}
	}

	groups := map[int][]int{}
	for i := range findings {
		r := find(i)
		groups[r] = append(groups[r], i)
	}
	if len(groups) == len(findings) {
		return findings
	}

	out := make([]Finding, 0, len(groups))
	for _, idxs := range groups {
		out = append(out, mergeGroup(findings, idxs))
	}
	SortFindings(out)
	return out
}

func correlationKeys(f Finding) []string {
	switch f.Kind {
	case KindVulnerability:
		if f.Package == nil {
			return nil
		}
		comp := strings.ToLower(f.Package.Ecosystem) + "|" + strings.ToLower(f.Package.Name) + "|" + f.Package.Version
		var keys []string
		for _, id := range f.IDs {
			switch id.Type {
			case "CVE", "GHSA", "GO", "RUSTSEC", "OSV":
				keys = append(keys, "dep|"+comp+"|"+strings.ToUpper(id.Value))
			}
		}
		return keys
	case KindCode:
		base := ""
		for _, id := range f.IDs {
			if id.Type == "CWE" {
				base = id.Value
				break
			}
		}
		if base == "" && len(f.Sources) > 0 {
			base = f.Sources[0].Rule
		}
		return []string{"code|" + base + "|" + primaryPath(&f) + "|" + contextHash(f.Evidence.Snippet)}
	case KindMisconfig:
		rule := ""
		if len(f.Sources) > 0 {
			rule = f.Sources[0].Rule
		}
		return []string{"misconfig|" + rule + "|" + primaryPath(&f)}
	}
	return nil
}

func mergeGroup(all []Finding, idxs []int) Finding {
	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })
	best := idxs[0]
	for _, i := range idxs[1:] {
		if comparePriority(all[i], all[best]) < 0 {
			best = i
		}
	}
	merged := all[best]
	merged.SeverityOthers = nil
	for _, i := range idxs {
		if i == best {
			continue
		}
		other := all[i]
		merged.Sources = appendUniqueSource(merged.Sources, other.Sources...)
		for _, id := range other.IDs {
			merged.AddID(id.Type, id.Value)
		}
		for _, loc := range other.Locations {
			merged.AddLocation(loc)
		}
		merged.Descriptions = appendUniqueDescription(merged.Descriptions, other.Descriptions...)
		merged.Remediation = appendUniqueRemediation(merged.Remediation, other.Remediation...)
		for _, ref := range other.References {
			merged.References = appendUniqueString(merged.References, ref)
		}
		merged.Priority = mergePriority(merged.Priority, other.Priority)
		if other.Severity.Normalized != merged.Severity.Normalized {
			merged.SeverityOthers = appendUniqueSeverity(merged.SeverityOthers, other.Severity)
		}
		if other.Fingerprint != "" && other.Fingerprint != merged.Fingerprint {
			if merged.Correlation == nil {
				merged.Correlation = &Correlation{}
			}
			merged.Correlation.MergedFingerprints = appendUniqueString(merged.Correlation.MergedFingerprints, other.Fingerprint)
		}
	}
	if len(merged.SeverityOthers) > 0 {
		sort.Slice(merged.SeverityOthers, func(i, j int) bool {
			if merged.SeverityOthers[i].Source == merged.SeverityOthers[j].Source {
				return merged.SeverityOthers[i].Normalized < merged.SeverityOthers[j].Normalized
			}
			return merged.SeverityOthers[i].Source < merged.SeverityOthers[j].Source
		})
	}
	sort.Strings(merged.References)
	if merged.Correlation != nil {
		for _, id := range merged.IDs {
			merged.Correlation.Aliases = appendUniqueString(merged.Correlation.Aliases, id.Value)
		}
		sort.Strings(merged.Correlation.Aliases)
		sort.Strings(merged.Correlation.MergedFingerprints)
	}
	return merged
}

// comparePriority ordena candidatos: mayor severidad, KEV, EPSS, CVSS y, por
// último, fingerprint.
func comparePriority(a, b Finding) int {
	if ra, rb := a.Severity.Normalized.Rank(), b.Severity.Normalized.Rank(); ra != rb {
		if ra > rb {
			return -1
		}
		return 1
	}
	if ka, kb := kev(a), kev(b); ka != kb {
		if ka {
			return -1
		}
		return 1
	}
	if ea, eb := epss(a), epss(b); ea != eb {
		if ea > eb {
			return -1
		}
		return 1
	}
	if ca, cb := cvss(a), cvss(b); ca != cb {
		if ca > cb {
			return -1
		}
		return 1
	}
	return strings.Compare(a.Fingerprint, b.Fingerprint)
}

func appendUniqueSeverity(dst []SeverityInfo, s SeverityInfo) []SeverityInfo {
	for _, d := range dst {
		if d.Source == s.Source && d.Original == s.Original && d.Normalized == s.Normalized {
			return dst
		}
	}
	return append(dst, s)
}

func appendUniqueSource(dst []SourceRef, src ...SourceRef) []SourceRef {
	for _, s := range src {
		found := false
		for _, d := range dst {
			if d.Engine == s.Engine && d.Rule == s.Rule {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	sort.Slice(dst, func(i, j int) bool {
		if dst[i].Engine == dst[j].Engine {
			return dst[i].Rule < dst[j].Rule
		}
		return dst[i].Engine < dst[j].Engine
	})
	return dst
}

func appendUniqueDescription(dst []Description, src ...Description) []Description {
	for _, s := range src {
		found := false
		for _, d := range dst {
			if d.Source == s.Source && d.Text == s.Text {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}

func appendUniqueRemediation(dst []Remediation, src ...Remediation) []Remediation {
	for _, s := range src {
		found := false
		for _, d := range dst {
			if d.Source == s.Source && d.Description == s.Description {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, s)
		}
	}
	return dst
}

func appendUniqueString(dst []string, s string) []string {
	for _, d := range dst {
		if d == s {
			return dst
		}
	}
	return append(dst, s)
}

func mergePriority(a, b *Priority) *Priority {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := *a
	if out.CVSSScore == nil {
		out.CVSSScore = b.CVSSScore
	}
	if out.CVSSVector == nil {
		out.CVSSVector = b.CVSSVector
	}
	if out.EPSS == nil {
		out.EPSS = b.EPSS
	}
	if out.KEV == nil {
		out.KEV = b.KEV
	}
	if out.Reachable == nil {
		out.Reachable = b.Reachable
	} else if b.Reachable != nil && *b.Reachable {
		out.Reachable = b.Reachable
	}
	return &out
}
