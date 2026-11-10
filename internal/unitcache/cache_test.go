package unitcache

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
	"github.com/CGCServicesSpA/cgc-scan/internal/version"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func req(root, engine, mode, db string) orchestrator.CacheRequest {
	return orchestrator.CacheRequest{
		EngineID: engine, EngineVersion: "1.0.0", Mode: mode, DBKey: db,
		Root: root, UnitID: "svc", UnitPath: "svc",
		Invocations: []runner.Invocation{{Engine: engine, Dir: filepath.Join(root, "svc"), Args: []string{"scan", "."}}},
	}
}

func TestKeyDependsOnMode(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "svc", "go.mod"), "module example.com/svc\n")
	write(t, filepath.Join(root, "svc", "main.go"), "package main\n")
	s := &Store{dir: t.TempDir()}

	deps := s.Key(req(root, "govulncheck", "deps", ""))
	source := s.Key(req(root, "eslint", "source", ""))
	if deps == source {
		t.Fatal("claves de motores distintos no pueden coincidir")
	}
	write(t, filepath.Join(root, "svc", "main.go"), "package main\n\nfunc f() {}\n")
	deps2 := s.Key(req(root, "govulncheck", "deps", ""))
	source2 := s.Key(req(root, "eslint", "source", ""))
	if deps2 != deps {
		t.Error("un cambio de código invalidó un motor de dependencias")
	}
	if source2 == source {
		t.Error("un cambio de código no invalidó un motor de código")
	}
	write(t, filepath.Join(root, "svc", "go.sum"), "x v1 h1:abc\n")
	deps3 := s.Key(req(root, "govulncheck", "deps", ""))
	if deps3 == deps2 {
		t.Error("un cambio de lockfile no invalidó el motor de dependencias")
	}
}

func TestKeyIncludesConfigDBAndVersion(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "svc", "go.mod"), "module x\n")
	s := &Store{dir: t.TempDir()}
	base := s.Key(req(root, "trivy", "full", "db1"))
	if s.Key(req(root, "trivy", "full", "db2")) == base {
		t.Error("un cambio de base no invalidó la clave")
	}
	r := req(root, "trivy", "full", "db1")
	r.Invocations[0].Args = []string{"scan", "--skip-dirs", "vendor"}
	if s.Key(r) == base {
		t.Error("un cambio de configuración efectiva no invalidó la clave")
	}
	r = req(root, "trivy", "full", "db1")
	r.EngineVersion = "2.0.0"
	if s.Key(r) == base {
		t.Error("un cambio de versión del motor no invalidó la clave")
	}
	old := version.Version
	version.Version = "9.9.9"
	defer func() { version.Version = old }()
	if s.Key(req(root, "trivy", "full", "db1")) == base {
		t.Error("un cambio de versión de la CLI no invalidó la clave")
	}
}

func TestStoreRoundTripAndKeyMismatch(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "svc", "go.mod"), "module x\n")
	paths := platform.Paths{ConfigDir: t.TempDir(), DataDir: t.TempDir(), CacheDir: t.TempDir()}
	s, err := Open(paths, root)
	if err != nil {
		t.Fatal(err)
	}
	r := req(root, "trivy", "full", "db1")
	if _, ok := s.Lookup(r); ok {
		t.Fatal("no debería haber resultado")
	}
	f := normalize.Finding{Fingerprint: strings.Repeat("a", 32), Kind: normalize.KindVulnerability, Title: "x", Severity: normalize.SeverityInfo{Normalized: normalize.SeverityHigh, Source: "trivy"}, Sources: []normalize.SourceRef{{Engine: "trivy"}}}
	if err := s.Save(r, orchestrator.CachedUnit{Status: "completed", Findings: []normalize.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Lookup(r)
	if !ok || got.Status != "completed" || len(got.Findings) != 1 {
		t.Fatalf("lookup = %+v, %v", got, ok)
	}
	// Cambiar el contenido invalida la clave aunque el archivo exista.
	write(t, filepath.Join(root, "svc", "go.mod"), "module y\n")
	if _, ok := s.Lookup(r); ok {
		t.Fatal("se reutilizó un resultado con clave vieja")
	}
	info, err := os.Stat(filepath.Join(s.Dir(), "units", "svc.trivy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos = %o", info.Mode().Perm())
	}
}

func TestCacheSkipDirsDoNotAffectKey(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "svc", "main.js"), "console.log(1)\n")
	write(t, filepath.Join(root, "svc", "node_modules", "x.js"), "x\n")
	s := &Store{dir: t.TempDir()}
	k1 := s.Key(req(root, "eslint", "source", ""))
	write(t, filepath.Join(root, "svc", "node_modules", "x.js"), "cambiado\n")
	if k2 := s.Key(req(root, "eslint", "source", "")); k2 != k1 {
		t.Fatal("los directorios intrínsecos no deberían invalidar la caché")
	}
}

func TestKeyIncludesImageButNotStagedMountSource(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "go.mod"), "module example.com/svc\n")
	base := orchestrator.CacheRequest{
		EngineID: "govulncheck", EngineVersion: "1.9.0", Mode: "deps",
		Root: root, UnitID: "root", UnitPath: ".",
		Invocations: []runner.Invocation{{
			Engine: "govulncheck", Dir: root, Args: []string{"govulncheck", "./..."},
			Image:  "cgc-scan/toolchain:go-1.22-govulncheck-1.9.0",
			Mounts: []runner.Mount{{Source: "/tmp/stage-a", Target: "/cgc-vulndb", ReadOnly: true}},
		}},
	}
	s := &Store{}
	first := s.Key(base)

	// El staging cambia de ruta en cada ejecución; la clave debe seguir igual.
	moved := base
	moved.Invocations = []runner.Invocation{base.Invocations[0]}
	moved.Invocations[0].Mounts = []runner.Mount{{Source: "/tmp/stage-b", Target: "/cgc-vulndb", ReadOnly: true}}
	if got := s.Key(moved); got != first {
		t.Fatal("la ruta del staging invalidó la caché")
	}

	// Una imagen distinta sí debe invalidar.
	otherImage := base
	otherImage.Invocations = []runner.Invocation{base.Invocations[0]}
	otherImage.Invocations[0].Image = "cgc-scan/toolchain:go-1.24-govulncheck-1.9.0"
	if got := s.Key(otherImage); got == first {
		t.Fatal("la imagen no participa en la clave")
	}

	// Un objetivo de montaje distinto cambia el contrato del motor.
	otherTarget := base
	otherTarget.Invocations = []runner.Invocation{base.Invocations[0]}
	otherTarget.Invocations[0].Mounts = []runner.Mount{{Source: "/tmp/stage-a", Target: "/otra", ReadOnly: true}}
	if got := s.Key(otherTarget); got == first {
		t.Fatal("el destino del montaje no participa en la clave")
	}
}
