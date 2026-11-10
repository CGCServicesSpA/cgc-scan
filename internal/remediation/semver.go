// Package remediation agrupa hallazgos por acción, calcula versiones objetivo,
// riesgo de ruptura, prioridad y próximas acciones deterministas.
package remediation

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Version es una versión comparable de cualquiera de los ecosistemas
// soportados. No se usa para afirmar compatibilidad: solo para ordenar y
// calcular el riesgo de ruptura.
type Version struct {
	Raw     string
	Epoch   int
	Release []int
	Pre     string
	Valid   bool
}

var numericSegment = regexp.MustCompile(`[0-9]+`)

// ParseVersion interpreta la versión según el ecosistema. Acepta prefijos
// habituales (v, =, ^, ~), restricciones de Cargo y metadatos de build.
func ParseVersion(ecosystem, raw string) Version {
	v := Version{Raw: strings.TrimSpace(raw)}
	if v.Raw == "" {
		return v
	}
	clean := strings.TrimSpace(v.Raw)
	clean = strings.TrimLeft(clean, "=^~<> ")
	if i := strings.IndexAny(clean, ", "); i >= 0 {
		clean = clean[:i]
	}
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return v
	}
	if strings.EqualFold(ecosystem, "Go") || strings.EqualFold(ecosystem, "go") {
		clean = strings.TrimPrefix(clean, "v")
	}
	if strings.EqualFold(ecosystem, "Packagist") || strings.EqualFold(ecosystem, "composer") {
		clean = strings.TrimPrefix(clean, "v")
	}
	clean = strings.TrimLeft(clean, "vV")
	// Epoch de PEP 440.
	if i := strings.Index(clean, "!"); i > 0 {
		if n, err := strconv.Atoi(clean[:i]); err == nil {
			v.Epoch = n
			clean = clean[i+1:]
		}
	}
	if i := strings.Index(clean, "+"); i >= 0 {
		clean = clean[:i]
	}
	// Pre-release: primer guion o sufijo no numérico tras el release.
	main := clean
	for i := 0; i < len(clean); i++ {
		c := clean[i]
		if c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			main = clean[:i]
			v.Pre = strings.ToLower(clean[i:])
			break
		}
	}
	if main == "" || numericSegment.FindString(main) == "" {
		return Version{Raw: v.Raw}
	}
	parts := strings.Split(main, ".")
	for _, p := range parts {
		if p == "" {
			v.Release = append(v.Release, 0)
			continue
		}
		digits := numericSegment.FindString(p)
		if digits == "" || digits != p {
			return Version{Raw: v.Raw}
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return Version{Raw: v.Raw}
		}
		v.Release = append(v.Release, n)
	}
	if len(v.Release) == 0 {
		return Version{Raw: v.Raw}
	}
	v.Valid = true
	return v
}

// CompareVersions devuelve -1, 0 o 1. Una versión inválida se considera
// menor que cualquier válida.
func CompareVersions(ecosystem, a, b string) int {
	return compareParsed(ParseVersion(ecosystem, a), ParseVersion(ecosystem, b))
}

func compareParsed(a, b Version) int {
	switch {
	case !a.Valid && !b.Valid:
		return 0
	case !a.Valid:
		return -1
	case !b.Valid:
		return 1
	}
	if a.Epoch != b.Epoch {
		return sign(a.Epoch - b.Epoch)
	}
	n := len(a.Release)
	if len(b.Release) > n {
		n = len(b.Release)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(a.Release) {
			x = a.Release[i]
		}
		if i < len(b.Release) {
			y = b.Release[i]
		}
		if x != y {
			return sign(x - y)
		}
	}
	// Una versión final es mayor que una pre-release.
	switch {
	case a.Pre == "" && b.Pre != "":
		return 1
	case a.Pre != "" && b.Pre == "":
		return -1
	case a.Pre != b.Pre:
		return strings.Compare(a.Pre, b.Pre)
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// Major devuelve el major efectivo. En Go, el sufijo /vN del módulo manda.
func Major(ecosystem, module, version string) int {
	if strings.EqualFold(ecosystem, "Go") || strings.EqualFold(ecosystem, "go") {
		if m := goModuleMajor(module); m > 0 {
			return m
		}
	}
	v := ParseVersion(ecosystem, version)
	if !v.Valid || len(v.Release) == 0 {
		return -1
	}
	return v.Release[0]
}

func goModuleMajor(module string) int {
	last := module
	if i := strings.LastIndex(module, "/"); i >= 0 {
		last = module[i+1:]
	}
	if len(last) < 2 || last[0] != 'v' {
		return 0
	}
	n, err := strconv.Atoi(last[1:])
	if err != nil || n < 2 {
		return 0
	}
	return n
}

// Target elige la versión objetivo: la mayor de las corregidas dentro del
// mismo major si existe alternativa; si no, la mayor global. Nunca inventa
// una versión que la fuente no haya declarado.
func Target(ecosystem, module, current string, fixed []string) (string, bool) {
	cur := ParseVersion(ecosystem, current)
	if !cur.Valid {
		return "", false
	}
	type candidate struct {
		raw string
		v   Version
	}
	var sameMajor []candidate
	var all []candidate
	curMajor := Major(ecosystem, module, current)
	for _, raw := range fixed {
		v := ParseVersion(ecosystem, raw)
		if !v.Valid || compareParsed(v, cur) <= 0 {
			continue
		}
		norm := normalizeTarget(ecosystem, raw)
		all = append(all, candidate{raw: norm, v: v})
		if curMajor < 0 || Major(ecosystem, module, norm) == curMajor {
			sameMajor = append(sameMajor, candidate{raw: norm, v: v})
		}
	}
	pool := all
	if len(sameMajor) > 0 {
		pool = sameMajor
	}
	if len(pool) == 0 {
		return "", false
	}
	sort.SliceStable(pool, func(i, j int) bool {
		if c := compareParsed(pool[i].v, pool[j].v); c != 0 {
			return c > 0
		}
		return pool[i].raw > pool[j].raw
	})
	return pool[0].raw, true
}

func normalizeTarget(ecosystem, raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimLeft(s, "=^~<> ")
	if i := strings.IndexAny(s, ", "); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if strings.EqualFold(ecosystem, "Go") && !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	return s
}

// BreakingRisk calcula patch|minor|major|unknown comparando las versiones.
func BreakingRisk(ecosystem, module, from, to string) string {
	a := ParseVersion(ecosystem, from)
	b := ParseVersion(ecosystem, to)
	if !a.Valid || !b.Valid {
		return "unknown"
	}
	ma, mb := Major(ecosystem, module, from), Major(ecosystem, module, to)
	if ma < 0 || mb < 0 {
		return "unknown"
	}
	if ma != mb {
		return "major"
	}
	minorA, minorB := segment(a, 1), segment(b, 1)
	switch {
	case minorA != minorB:
		return "minor"
	case segment(a, 2) != segment(b, 2):
		return "patch"
	default:
		if compareParsed(a, b) != 0 {
			return "patch"
		}
		return "unknown"
	}
}

func segment(v Version, i int) int {
	if i < len(v.Release) {
		return v.Release[i]
	}
	return 0
}

// Command devuelve la sugerencia de aplicación por ecosistema. No se ejecuta.
func Command(ecosystem, module, name, target string, direct *bool, via string) (apply, override string) {
	eco := strings.ToLower(ecosystem)
	switch {
	case eco == "go" || eco == "golang":
		apply = "go get " + name + "@" + target + " && go mod tidy"
		if direct != nil && !*direct {
			override = "go mod edit -replace " + name + "=" + name + "@" + target
		}
	case eco == "npm" || eco == "node" || eco == "javascript" || eco == "typescript":
		apply = "npm install " + name + "@" + target
		if direct != nil && !*direct {
			override = "npm pkg set overrides." + name + "=" + target
		}
	case eco == "crates.io" || eco == "cargo" || eco == "rust":
		apply = "cargo update -p " + name + " --precise " + target
	case eco == "pypi" || eco == "pip" || eco == "python":
		apply = "pip install " + name + "==" + target
	case eco == "packagist" || eco == "composer" || eco == "php":
		apply = "composer require " + name + ":" + target + " --with-all-dependencies"
	}
	return apply, override
}
