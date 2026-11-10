package adapter

import "testing"

func TestContainerPath(t *testing.T) {
	cases := map[string]string{
		"/src/internal/app/main.go": "internal/app/main.go",
		"/src/go.mod":               "go.mod",
		"/src":                      ".",
	}
	for in, want := range cases {
		got, ok := ContainerPath(ContainerRoot, in)
		if !ok || got != want {
			t.Fatalf("ContainerPath(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	if _, ok := ContainerPath(ContainerRoot, "/otro/a.go"); ok {
		t.Fatal("se aceptó una ruta fuera del proyecto")
	}
}

func TestRelativePathPrefersHostThenContainer(t *testing.T) {
	if got := RelativePath("/repo", ContainerRoot, "/repo/svc/a.go"); got != "svc/a.go" {
		t.Fatalf("ruta del host = %q", got)
	}
	if got := RelativePath("/repo", ContainerRoot, "/src/svc/a.go"); got != "svc/a.go" {
		t.Fatalf("ruta del contenedor = %q", got)
	}
	if got := RelativePath("/repo", ContainerRoot, "svc/a.go"); got != "svc/a.go" {
		t.Fatalf("ruta relativa = %q", got)
	}
	if got := RelativePath("/repo", ContainerRoot, "/otro/a.go"); got != "/otro/a.go" {
		t.Fatalf("ruta externa = %q", got)
	}
}

func TestContainerUnitDir(t *testing.T) {
	c := &Container{Root: ContainerRoot}
	if got := c.UnitDir("."); got != "/src" {
		t.Fatalf("unidad raíz = %q", got)
	}
	if got := c.UnitDir("svc/api"); got != "/src/svc/api" {
		t.Fatalf("subunidad = %q", got)
	}
}
