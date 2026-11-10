package remediation

import "testing"

func TestTargetVersionTable(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		current   string
		fixed     []string
		want      string
		ok        bool
	}{
		{
			name: "x/text elige la mayor del mismo major", ecosystem: "Go", current: "v0.3.0",
			fixed: []string{"0.3.3", "0.3.7", "0.3.8", "0.39.0", "0.41.0"}, want: "v0.41.0", ok: true,
		},
		{
			name: "no cruza de major si hay alternativa", ecosystem: "npm", current: "1.2.0",
			fixed: []string{"1.2.3", "1.9.0", "2.0.0"}, want: "1.9.0", ok: true,
		},
		{
			name: "sin alternativa en el major toma la mayor global", ecosystem: "npm", current: "1.2.0",
			fixed: []string{"2.0.0", "2.3.0"}, want: "2.3.0", ok: true,
		},
		{
			name: "PEP 440", ecosystem: "PyPI", current: "1.4.0",
			fixed: []string{"1.4.2", "1.5.0", "2.0.0"}, want: "1.5.0", ok: true,
		},
		{
			name: "Composer", ecosystem: "Packagist", current: "v2.1.0",
			fixed: []string{"v2.1.4", "v2.3.0", "v3.0.0"}, want: "v2.3.0", ok: true,
		},
		{
			name: "Cargo con restricción", ecosystem: "crates.io", current: "0.2.1",
			fixed: []string{">=0.2.23, <0.3.0"}, want: "0.2.23", ok: true,
		},
		{
			name: "sin versión superior", ecosystem: "Go", current: "v1.0.0",
			fixed: []string{"1.0.0"}, ok: false,
		},
		{
			name: "versiones inválidas", ecosystem: "npm", current: "1.0.0",
			fixed: []string{"desconocida"}, ok: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Target(tt.ecosystem, "", tt.current, tt.fixed)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("Target = %q,%v; want %q,%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestBreakingRiskTable(t *testing.T) {
	tests := []struct {
		eco      string
		module   string
		from, to string
		want     string
	}{
		{"Go", "golang.org/x/text", "v0.3.0", "v0.41.0", "minor"},
		{"Go", "example.com/m/v2", "v2.1.0", "v2.2.0", "minor"},
		{"Go", "example.com/m", "v1.2.3", "v2.0.0", "major"},
		{"npm", "", "1.2.3", "1.2.4", "patch"},
		{"npm", "", "1.2.3", "1.3.0", "minor"},
		{"npm", "", "1.2.3", "2.0.0", "major"},
		{"PyPI", "", "1!2.3.4", "1!2.4.0", "minor"},
		{"Packagist", "", "v1.2.3", "v2.0.0", "major"},
		{"crates.io", "", "0.2.1", "0.2.23", "patch"},
		{"npm", "", "1.0.0", "no-válida", "unknown"},
	}
	for _, tt := range tests {
		if got := BreakingRisk(tt.eco, tt.module, tt.from, tt.to); got != tt.want {
			t.Errorf("BreakingRisk(%s,%s,%s,%s) = %q; want %q", tt.eco, tt.module, tt.from, tt.to, got, tt.want)
		}
	}
}

func TestComparePrereleaseAndBuild(t *testing.T) {
	if CompareVersions("PyPI", "1.0.0rc1", "1.0.0") >= 0 {
		t.Fatal("una pre-release debe ser anterior a la versión final")
	}
	if CompareVersions("npm", "1.0.0+build.2", "1.0.0+build.10") != 0 {
		t.Fatal("el build metadata no participa en la comparación")
	}
	if CompareVersions("Packagist", "v1.2", "1.2.0") != 0 {
		t.Fatal("1.2 y 1.2.0 deben ser equivalentes")
	}
}
