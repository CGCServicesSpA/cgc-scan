// Package normalize define el modelo de hallazgo, la severidad común, la
// huella estable y el orden determinista del reporte (design §5.3, §9.1).
package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
)

// Kind clasifica un hallazgo.
type Kind string

const (
	KindVulnerability Kind = "vulnerability"
	KindSecret        Kind = "secret"
	KindMisconfig     Kind = "misconfig"
	KindCode          Kind = "code"
)

// Severity es la escala común del PRD §9.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "info"
	SeverityUnknown       Severity = "unknown"
)

// Rank devuelve la posición en la escala; mayor es más grave. `info` queda por
// debajo de `low` y `unknown` por debajo de `info`, pero unknown no se descarta
// en silencio: la política decide si cuenta.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	default:
		return 0
	}
}

// Valid informa si la severidad pertenece a la escala.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational, SeverityUnknown:
		return true
	}
	return false
}

// Max devuelve la mayor de dos severidades verificadas.
func Max(a, b Severity) Severity {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// NormalizeSeverity mapea la severidad original de un motor a la escala común
// (design §8.2). Un valor vacío o desconocido queda como unknown, nunca como
// low por defecto.
func NormalizeSeverity(engine, original string) Severity {
	v := strings.ToLower(strings.TrimSpace(original))
	switch strings.ToLower(engine) {
	case "trivy":
		switch v {
		case "critical":
			return SeverityCritical
		case "high":
			return SeverityHigh
		case "medium":
			return SeverityMedium
		case "low":
			return SeverityLow
		default:
			return SeverityUnknown
		}
	case "bandit":
		switch v {
		case "high":
			return SeverityHigh
		case "medium":
			return SeverityMedium
		case "low":
			return SeverityLow
		default:
			return SeverityUnknown
		}
	case "semgrep":
		switch v {
		case "error":
			return SeverityHigh
		case "warning":
			return SeverityMedium
		case "info":
			return SeverityInformational
		default:
			return SeverityUnknown
		}
	default:
		// govulncheck y cargo-audit no suelen entregar severidad; eslint y
		// psalm pasan por la tabla de categorías de su adaptador.
		switch v {
		case "critical", "high", "medium", "low", "info", "unknown":
			return Severity(v)
		}
		return SeverityUnknown
	}
}

// Description es una descripción con su procedencia.
type Description struct {
	Text   string `json:"text"`
	Source string `json:"source"`
}

// SeverityInfo conserva la severidad original y la normalizada.
type SeverityInfo struct {
	Original   string   `json:"original"`
	Normalized Severity `json:"normalized"`
	Source     string   `json:"source"`
}

// Confidence es la confianza declarada por la fuente; nunca se inventa.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Identifier es un CVE, GHSA, CWE, RUSTSEC, GO- u otro identificador.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// PackageRef describe el componente afectado.
type PackageRef struct {
	Ecosystem    string  `json:"ecosystem"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	FixedVersion *string `json:"fixed_version"`
}

// Location es una ubicación relativa a la raíz del proyecto.
type Location struct {
	Path        string `json:"path"`
	StartLine   *int   `json:"start_line,omitempty"`
	EndLine     *int   `json:"end_line,omitempty"`
	StartColumn *int   `json:"start_column,omitempty"`
	EndColumn   *int   `json:"end_column,omitempty"`
}

// Evidence es el fragmento ya enmascarado. Redacted indica si se aplicó
// enmascarado (siempre verdadero para secretos).
type Evidence struct {
	Snippet  string `json:"snippet"`
	Redacted bool   `json:"redacted"`
}

// SourceRef identifica el motor, su versión y la regla.
type SourceRef struct {
	Engine  string `json:"engine"`
	Version string `json:"version,omitempty"`
	Rule    string `json:"rule,omitempty"`
}

// Remediation conserva la recomendación del motor o advisory.
type Remediation struct {
	Description string `json:"description"`
	Source      string `json:"source"`
}

// Priority agrupa datos de priorización locales. Los punteros nulos significan
// que la fuente no los entregó.
type Priority struct {
	CVSSScore  *float64 `json:"cvss_score,omitempty"`
	CVSSVector *string  `json:"cvss_vector,omitempty"`
	EPSS       *float64 `json:"epss,omitempty"`
	KEV        *bool    `json:"kev,omitempty"`
	Reachable  *bool    `json:"reachable,omitempty"`
}

// FindingPolicy indica si el hallazgo está suprimido y por qué.
type FindingPolicy struct {
	Status               string `json:"status"`
	SuppressedReason     string `json:"suppressed_reason,omitempty"`
	ExceptionFingerprint string `json:"exception_fingerprint,omitempty"`
}

// Correlation conserva alias y huellas fusionadas.
type Correlation struct {
	Aliases            []string `json:"aliases,omitempty"`
	MergedFingerprints []string `json:"merged_fingerprints,omitempty"`
}

// Finding es el hallazgo normalizado del contrato.
type Finding struct {
	Fingerprint  string        `json:"fingerprint"`
	Kind         Kind          `json:"kind"`
	Title        string        `json:"title"`
	Descriptions []Description `json:"descriptions,omitempty"`
	Severity     SeverityInfo  `json:"severity"`
	Confidence   *Confidence   `json:"confidence,omitempty"`
	IDs          []Identifier  `json:"ids,omitempty"`
	Package      *PackageRef   `json:"package,omitempty"`
	Locations    []Location    `json:"locations,omitempty"`
	Evidence     Evidence      `json:"evidence"`
	Sources      []SourceRef   `json:"sources"`
	Remediation  []Remediation `json:"remediation,omitempty"`
	Priority     *Priority     `json:"priority,omitempty"`
	Policy       FindingPolicy `json:"policy"`
	Correlation  *Correlation  `json:"correlation,omitempty"`
}

// Fingerprint calcula la huella v1 a partir de la identidad estable. Es
// independiente del número de línea (design §9.1).
func Fingerprint(f *Finding) string {
	var identity string
	switch f.Kind {
	case KindVulnerability:
		pkg := ""
		if f.Package != nil {
			pkg = strings.ToLower(f.Package.Ecosystem) + "|" + strings.ToLower(f.Package.Name) + "|" + f.Package.Version
		}
		identity = pkg + "|" + canonicalAdvisory(f.IDs) + "|" + primaryPath(f)
	case KindCode:
		rule := ""
		if len(f.Sources) > 0 {
			rule = f.Sources[0].Rule
		}
		identity = rule + "|" + primaryPath(f) + "|" + contextHash(f.Evidence.Snippet)
	case KindMisconfig:
		rule := ""
		if len(f.Sources) > 0 {
			rule = f.Sources[0].Rule
		}
		identity = rule + "|" + primaryPath(f)
	case KindSecret:
		// El adaptador debe usar FingerprintSecret, que conoce el valor. Si
		// llega aquí ya hay una huella en Evidence.Snippet.
		identity = "secret|" + primaryPath(f) + "|" + f.Evidence.Snippet
	default:
		identity = f.Title
	}
	return hashIdentity(identity)
}

// FingerprintSecret calcula la huella de un secreto con la sal por instalación.
// El valor nunca se almacena.
func FingerprintSecret(m *masking.Masker, rule, path, value string) string {
	return hashIdentity("secret|" + rule + "|" + path + "|" + m.Fingerprint(value))
}

func hashIdentity(identity string) string {
	sum := sha256.Sum256([]byte("v1|" + identity))
	return hex.EncodeToString(sum[:])[:32]
}

// contextHash normaliza el contexto (sin espacios) para que mover el hallazgo
// de línea no cambie la huella, pero un cambio de código sí.
func contextHash(snippet string) string {
	norm := strings.Join(strings.Fields(snippet), "")
	// El contexto vacío no debe colapsar todos los hallazgos de una regla en
	// la misma ruta: se usa un marcador explícito.
	if norm == "" {
		norm = "sin-contexto"
	}
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])[:16]
}

func primaryPath(f *Finding) string {
	if len(f.Locations) == 0 {
		return ""
	}
	return f.Locations[0].Path
}

// canonicalAdvisory elige un identificador estable entre motores.
func canonicalAdvisory(ids []Identifier) string {
	order := map[string]int{"CVE": 0, "GHSA": 1, "OSV": 2, "GO": 3, "RUSTSEC": 4, "CWE": 5}
	best := ""
	bestRank := 99
	for _, id := range ids {
		r, ok := order[id.Type]
		if !ok {
			continue
		}
		if r < bestRank || (r == bestRank && id.Value < best) {
			best = strings.ToUpper(id.Value)
			bestRank = r
		}
	}
	if best == "" {
		for _, id := range ids {
			if id.Value != "" && (best == "" || id.Value < best) {
				best = id.Value
			}
		}
	}
	return best
}

// SortFindings ordena por severidad normalizada, priorización disponible
// (KEV, EPSS, CVSS) y fingerprint. Es estable y total.
func SortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := a.Severity.Normalized.Rank(), b.Severity.Normalized.Rank(); ra != rb {
			return ra > rb
		}
		if ka, kb := kev(a), kev(b); ka != kb {
			return ka
		}
		if ea, eb := epss(a), epss(b); ea != eb {
			return ea > eb
		}
		if ca, cb := cvss(a), cvss(b); ca != cb {
			return ca > cb
		}
		return a.Fingerprint < b.Fingerprint
	})
}

func kev(f Finding) bool {
	return f.Priority != nil && f.Priority.KEV != nil && *f.Priority.KEV
}

func epss(f Finding) float64 {
	if f.Priority != nil && f.Priority.EPSS != nil {
		return *f.Priority.EPSS
	}
	return 0
}

func cvss(f Finding) float64 {
	if f.Priority != nil && f.Priority.CVSSScore != nil {
		return *f.Priority.CVSSScore
	}
	return 0
}

// AddLocation agrega una ubicación evitando duplicados exactos.
func (f *Finding) AddLocation(loc Location) {
	for _, l := range f.Locations {
		if l.Path == loc.Path && eqInt(l.StartLine, loc.StartLine) && eqInt(l.EndLine, loc.EndLine) {
			return
		}
	}
	f.Locations = append(f.Locations, loc)
}

func eqInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// AddID agrega un identificador evitando duplicados.
func (f *Finding) AddID(kind, value string) {
	if value == "" {
		return
	}
	for _, id := range f.IDs {
		if id.Type == kind && id.Value == value {
			return
		}
	}
	f.IDs = append(f.IDs, Identifier{Type: kind, Value: value})
}

// String devuelve una representación corta para logs, sin evidencia.
func (f Finding) String() string {
	return fmt.Sprintf("%s %s/%s %s", f.Fingerprint, f.Kind, f.Severity.Normalized, f.Title)
}
