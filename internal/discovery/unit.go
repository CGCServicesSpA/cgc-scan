// Package discovery detecta la raíz del proyecto, sus unidades y las
// exclusiones aplicables (PRD §4.4, design §9.4).
package discovery

import "sort"

// Language es un lenguaje soportado en v1.
type Language string

const (
	Go         Language = "go"
	JavaScript Language = "javascript"
	TypeScript Language = "typescript"
	PHP        Language = "php"
	Rust       Language = "rust"
	Python     Language = "python"
)

// Origin es el origen de una exclusión. Solo las elegidas marcan el escaneo
// como parcial.
type Origin string

const (
	OriginIntrinsic Origin = "intrinsic"
	OriginUser      Origin = "user"
	OriginPolicy    Origin = "policy"
	OriginCLI       Origin = "cli"
)

// Elected informa si el origen corresponde a una decisión de cobertura.
func (o Origin) Elected() bool {
	return o == OriginUser || o == OriginPolicy || o == OriginCLI
}

// Unit es una unidad de proyecto analizable.
type Unit struct {
	ID        string     `json:"id"`
	Path      string     `json:"path"`
	Kind      string     `json:"kind"`
	Languages []Language `json:"languages"`
	Manifests []string   `json:"manifests,omitempty"`
}

// Exclusion registra un patrón excluido y su origen.
type Exclusion struct {
	Pattern   string   `json:"pattern"`
	Origin    Origin   `json:"origin"`
	Reason    string   `json:"reason,omitempty"`
	AppliedTo []string `json:"applied_to,omitempty"`
}

// Result es el producto del descubrimiento, antes del plan de cobertura.
type Result struct {
	Root       string
	Units      []Unit
	Exclusions []Exclusion
	// Partial es verdadero si hay alguna exclusión elegida.
	Partial bool
}

// IntrinsicExclusions son las exclusiones que no pueden desactivarse.
func IntrinsicExclusions() []Exclusion {
	patterns := []struct{ pattern, reason string }{
		{"**/.git/**", "metadatos internos de Git"},
		{"**/node_modules/**", "dependencias instaladas de JavaScript"},
		{"**/vendor/**", "dependencias instaladas de Go/PHP"},
		{"**/.venv/**", "entorno virtual de Python"},
		{"**/target/**", "salidas de build de Rust"},
		{"**/dist/**", "salidas de build"},
		{"**/build/**", "salidas de build"},
		{"**/.next/**", "salidas de build de Next.js"},
		{"**/coverage/**", "salidas de cobertura de pruebas"},
	}
	out := make([]Exclusion, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, Exclusion{Pattern: p.pattern, Origin: OriginIntrinsic, Reason: p.reason})
	}
	return out
}

// SortUnits ordena por ruta para que el reporte sea determinista.
func SortUnits(units []Unit) {
	sort.Slice(units, func(i, j int) bool {
		if units[i].Path == units[j].Path {
			return units[i].ID < units[j].ID
		}
		return units[i].Path < units[j].Path
	})
}
