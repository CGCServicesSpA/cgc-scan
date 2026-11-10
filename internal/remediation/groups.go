package remediation

import (
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// Build agrupa los hallazgos en acciones de remediación deterministas.
// Un grupo de dependencias incluye solo hallazgos con una versión corregida
// declarada; los que no la tienen siguen visibles en findings y no se agrupan.
func Build(doc *report.Document) []report.RemediationGroup {
	if doc == nil {
		return []report.RemediationGroup{}
	}
	groups := map[string]*report.RemediationGroup{}
	add := func(g report.RemediationGroup) {
		if cur, ok := groups[g.ID]; ok {
			cur.Fixes = append(cur.Fixes, g.Fixes...)
			if normalize.Max(cur.MaxSeverity, g.MaxSeverity) != cur.MaxSeverity {
				cur.MaxSeverity = g.MaxSeverity
			}
			if g.PriorityScore > cur.PriorityScore {
				cur.PriorityScore = g.PriorityScore
			}
			cur.Locations += g.Locations
			return
		}
		groups[g.ID] = &g
	}

	for i := range doc.Findings {
		f := &doc.Findings[i]
		if f.Policy.Status == "suppressed" {
			continue
		}
		unit := projectstate.UnitForFinding(doc, f)
		score, _ := Score(*f)
		switch f.Kind {
		case normalize.KindVulnerability:
			if f.Package == nil {
				continue
			}
			fixed := fixedVersions(doc, unit, f)
			if len(fixed) == 0 {
				continue
			}
			target, ok := Target(f.Package.Ecosystem, f.Package.Name, f.Package.Version, fixed)
			if !ok {
				continue
			}
			id := dependencyID(f.Package.Ecosystem, f.Package.Name)
			g := report.RemediationGroup{
				ID: id, Kind: "dependency_upgrade", Unit: unit,
				Package: &report.GroupPackage{
					Ecosystem: f.Package.Ecosystem, Name: f.Package.Name,
					From: f.Package.Version, To: target,
				},
				Fixes:         []string{f.Fingerprint},
				MaxSeverity:   f.Severity.Normalized,
				PriorityScore: score,
				BreakingRisk:  BreakingRisk(f.Package.Ecosystem, f.Package.Name, f.Package.Version, target),
				Direct:        f.Package.Direct,
			}
			apply, override := Command(f.Package.Ecosystem, f.Package.Name, f.Package.Name, target, f.Package.Direct, f.Package.Via)
			g.Commands = report.GroupCommands{Apply: apply, Override: override, Origin: "cgc-scan"}
			if f.Package.Direct != nil && !*f.Package.Direct && f.Package.Via != "" {
				g.Note = "Dependencia transitiva: llega por " + f.Package.Via + ". Sube esa dependencia directa o aplica el override; el comando del paquete vulnerable por sí solo puede no compilar."
			}
			add(g)
		case normalize.KindCode:
			rule := sourceRule(f)
			file := primaryPath(f)
			g := report.RemediationGroup{
				ID: codeID(unit, rule, file), Kind: "code_fix", Unit: unit,
				File: file, Rule: rule, Fixes: []string{f.Fingerprint},
				Locations: len(f.Locations), MaxSeverity: f.Severity.Normalized,
				PriorityScore: score, BreakingRisk: "unknown",
				Commands: report.GroupCommands{Origin: "cgc-scan"},
				Note:     "Corrige todas las ubicaciones del archivo para esta regla.",
			}
			add(g)
		case normalize.KindSecret:
			rule := sourceRule(f)
			g := report.RemediationGroup{
				ID: secretID(unit, rule, f.Fingerprint), Kind: "secret_rotation", Unit: unit,
				Rule: rule, Fixes: []string{f.Fingerprint},
				MaxSeverity: f.Severity.Normalized, PriorityScore: score,
				BreakingRisk: "unknown",
				Commands:     report.GroupCommands{Origin: "cgc-scan"},
				Note:         "Revoca y rota la credencial; retírala del código y del historial.",
			}
			add(g)
		case normalize.KindMisconfig:
			rule := sourceRule(f)
			file := primaryPath(f)
			g := report.RemediationGroup{
				ID: configID(unit, rule, file), Kind: "config_fix", Unit: unit,
				File: file, Rule: rule, Fixes: []string{f.Fingerprint},
				MaxSeverity: f.Severity.Normalized, PriorityScore: score,
				BreakingRisk: "unknown",
				Commands:     report.GroupCommands{Origin: "cgc-scan"},
			}
			add(g)
		}
	}

	out := make([]report.RemediationGroup, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.Fixes)
		g.Fixes = dedupeStrings(g.Fixes)
		g.Verification = verificationFor(doc, *g)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PriorityScore != out[j].PriorityScore {
			return out[i].PriorityScore > out[j].PriorityScore
		}
		if out[i].MaxSeverity.Rank() != out[j].MaxSeverity.Rank() {
			return out[i].MaxSeverity.Rank() > out[j].MaxSeverity.Rank()
		}
		return out[i].ID < out[j].ID
	})
	resolveCollisions(out)
	return out
}

// fixedVersions reúne las versiones corregidas declaradas por cualquier motor
// para el mismo paquete en la misma unidad. Correlacionar es esencial: Trivy y
// govulncheck pueden describir el mismo aviso con huellas distintas.
func fixedVersions(doc *report.Document, unit string, target *normalize.Finding) []string {
	var out []string
	if target.Package == nil {
		return out
	}
	for i := range doc.Findings {
		f := &doc.Findings[i]
		if f.Package == nil || f.Package.FixedVersion == nil || *f.Package.FixedVersion == "" {
			continue
		}
		if !strings.EqualFold(f.Package.Ecosystem, target.Package.Ecosystem) ||
			f.Package.Name != target.Package.Name {
			continue
		}
		if projectstate.UnitForFinding(doc, f) != unit {
			continue
		}
		out = append(out, *f.Package.FixedVersion)
	}
	return out
}

func verificationFor(doc *report.Document, g report.RemediationGroup) report.GroupVerification {
	v := report.GroupVerification{
		Status: "blocked", Recipes: []normalize.VerificationRecipe{}, Missing: []string{},
		Verify: "cgc-scan verify " + g.ID,
	}
	if g.Kind == "secret_rotation" {
		v.Note = "Un secreto no se valida con tests ni build: exige revocar y rotar la credencial."
		return v
	}
	var sample *normalize.Verification
	for _, fp := range g.Fixes {
		for i := range doc.Findings {
			if doc.Findings[i].Fingerprint != fp {
				continue
			}
			if doc.Findings[i].Verification != nil {
				sample = doc.Findings[i].Verification
			}
		}
		if sample != nil {
			break
		}
	}
	if sample == nil {
		var missing []string
		has := map[string]bool{}
		for _, r := range doc.Validation.Recipes {
			if r.Unit != g.Unit {
				continue
			}
			has[r.Kind] = true
			v.Recipes = append(v.Recipes, normalize.VerificationRecipe{
				Unit: r.Unit, Kind: r.Kind, Command: r.Command, Workdir: r.Workdir, Origin: r.Origin,
			})
		}
		for _, kind := range []string{"test", "build"} {
			if !has[kind] {
				missing = append(missing, kind)
			}
		}
		v.Missing = missing
		if len(missing) == 0 {
			v.Status = "ready"
		} else {
			v.Note = "Faltan recetas confirmadas: " + strings.Join(missing, ", ") + "."
		}
		return v
	}
	v.Status = sample.Status
	v.Recipes = append(v.Recipes, sample.Recipes...)
	v.Missing = append(v.Missing, sample.Missing...)
	v.Note = sample.Note
	return v
}

func dependencyID(ecosystem, name string) string {
	eco := strings.ToLower(ecosystem)
	switch eco {
	case "go", "golang":
		eco = "go"
	case "npm", "node", "javascript", "typescript":
		eco = "npm"
	case "crates.io", "cargo", "rust":
		eco = "cargo"
	case "pypi", "pip", "python":
		eco = "pip"
	case "packagist", "composer", "php":
		eco = "composer"
	}
	name = strings.NewReplacer(" ", "", "\t", "", "@", "").Replace(strings.ToLower(name))
	return "rg-" + eco + "-" + name
}

func codeID(unit, rule, file string) string {
	return "rg-code-" + slug(unit) + "-" + slug(rule) + "-" + slug(file)
}

func secretID(unit, rule, fingerprint string) string {
	fp := fingerprint
	if len(fp) > 8 {
		fp = fp[:8]
	}
	return "rg-secret-" + slug(unit) + "-" + slug(rule) + "-" + slug(fp)
}

func configID(unit, rule, file string) string {
	return "rg-config-" + slug(unit) + "-" + slug(rule) + "-" + slug(file)
}

func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

func sourceRule(f *normalize.Finding) string {
	if len(f.Sources) > 0 {
		return f.Sources[0].Rule
	}
	return ""
}

func primaryPath(f *normalize.Finding) string {
	if len(f.Locations) > 0 {
		return f.Locations[0].Path
	}
	return ""
}

func resolveCollisions(groups []report.RemediationGroup) {
	count := map[string]int{}
	for _, g := range groups {
		count[g.ID]++
	}
	for i := range groups {
		if count[groups[i].ID] <= 1 {
			continue
		}
		groups[i].ID = groups[i].ID + "-" + slug(groups[i].Unit)
	}
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := in[:0]
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
