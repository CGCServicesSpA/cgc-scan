package toolchain

import (
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

func adapterFixture(t *testing.T, id string) manifest.Adapter {
	t.Helper()
	ms, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	a, err := ms.Adapter(id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestPlanRendersEntrypointReset(t *testing.T) {
	cases := []struct {
		lang discovery.Language
		id   string
	}{
		{discovery.Go, "govulncheck"},
		{discovery.JavaScript, "eslint"},
		{discovery.PHP, "psalm"},
		{discovery.Rust, "cargo-audit"},
		{discovery.Python, "bandit"},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			plan, err := NewPlan(Spec{Language: tc.lang}, adapterFixture(t, tc.id), "arm64")
			if err != nil {
				t.Fatal(err)
			}
			out := string(plan.Render("base@sha256:abc"))
			if !strings.Contains(out, "FROM base@sha256:abc") {
				t.Fatalf("no se sustituyó la base: %s", out)
			}
			if strings.Contains(out, "{{BASE}}") {
				t.Fatalf("quedó el marcador: %s", out)
			}
			if !strings.Contains(out, "ENTRYPOINT []") {
				t.Fatalf("la imagen debe anular el entrypoint: %s", out)
			}
			if !strings.Contains(plan.Tag, "cgc-scan/toolchain:") {
				t.Fatalf("tag = %q", plan.Tag)
			}
		})
	}
}

func TestPlanPinsAdapterVersion(t *testing.T) {
	plan, err := NewPlan(Spec{Language: discovery.Go, Version: "1.22"}, adapterFixture(t, "govulncheck"), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	out := string(plan.Render("golang:1.22@sha256:abc"))
	if !strings.Contains(out, "govulncheck@v1.9.0") {
		t.Fatalf("la versión del adaptador no está fijada: %s", out)
	}
	if !strings.Contains(plan.Tag, "govulncheck-1.9.0") {
		t.Fatalf("tag = %q", plan.Tag)
	}
}

func TestPlanCargoAuditPicksLinuxArchive(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		plan, err := NewPlan(Spec{Language: discovery.Rust, Version: "1.75"}, adapterFixture(t, "cargo-audit"), arch)
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Artifacts) != 1 || !strings.Contains(plan.Artifacts[0].URL, "linux") {
			t.Fatalf("arch %s: artifacts = %+v", arch, plan.Artifacts)
		}
	}
}

func TestPlanNodeEmbedsPinnedTree(t *testing.T) {
	plan, err := NewPlan(Spec{Language: discovery.JavaScript}, adapterFixture(t, "eslint"), "arm64")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"package.json", "package-lock.json", "cgc-eslint.config.mjs"} {
		if len(plan.Files[name]) == 0 {
			t.Fatalf("falta %s en el contexto", name)
		}
	}
	if !strings.Contains(string(plan.Render("x")), "npm ci") {
		t.Fatal("el árbol de ESLint no se instala con npm ci")
	}
}

func TestTagIsDeterministic(t *testing.T) {
	a := TagFor(Spec{Language: discovery.Go, Version: "1.22.3"}, "govulncheck", "1.9.0")
	b := TagFor(Spec{Language: discovery.Go, Version: "1.22.3"}, "govulncheck", "1.9.0")
	if a != b {
		t.Fatalf("tag no determinista: %q != %q", a, b)
	}
	if c := TagFor(Spec{Language: discovery.Go}, "govulncheck", "1.9.0"); !strings.Contains(c, "default") {
		t.Fatalf("tag sin versión = %q", c)
	}
}
