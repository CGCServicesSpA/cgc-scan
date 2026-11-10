package cli

import (
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/orchestrator"
	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
)

func TestAdapterLanguages(t *testing.T) {
	if got := adapterLanguages("eslint"); len(got) != 2 || got[0] != discovery.JavaScript {
		t.Fatalf("eslint = %v", got)
	}
	if got := adapterLanguages("govulncheck"); len(got) != 1 || got[0] != discovery.Go {
		t.Fatalf("govulncheck = %v", got)
	}
	if got := adapterLanguages("desconocido"); got != nil {
		t.Fatalf("desconocido = %v", got)
	}
}

func TestEngineModeIsDockerWhenContainerized(t *testing.T) {
	images := map[string]*adapter.Container{"root": {Image: "img"}}
	if got := engineMode("library", images); got != "docker" {
		t.Fatalf("modo = %q", got)
	}
	if got := engineMode("global", nil); got != "global" {
		t.Fatalf("modo = %q", got)
	}
}

func TestSingleImageOnlyWhenAllUnitsShareIt(t *testing.T) {
	one := map[string]*adapter.Container{
		"a": {Image: "img:1"}, "b": {Image: "img:1"},
	}
	if got := singleImage(one); got != "img:1" {
		t.Fatalf("imagen = %q", got)
	}
	two := map[string]*adapter.Container{
		"a": {Image: "img:1"}, "b": {Image: "img:2"},
	}
	if got := singleImage(two); got != "" {
		t.Fatalf("imagen = %q, se esperaba vacía", got)
	}
}

func TestAnyContainerIgnoresHostEngines(t *testing.T) {
	if anyContainer([]orchestrator.Engine{{ID: "eslint", Mode: "global"}}) {
		t.Fatal("un motor del host no es contenedor")
	}
	if !anyContainer([]orchestrator.Engine{{ID: "eslint", Mode: "docker"}}) {
		t.Fatal("un motor docker es contenedor")
	}
}

func TestBaseDescriptionIsDeterministic(t *testing.T) {
	img := provision.ToolchainImage{Base: "golang:1.22.3", Digest: "sha256:abc"}
	built := img
	built.Built = true
	if baseDescription(img) != baseDescription(built) {
		t.Fatal("el detalle de preparación cambia según si la imagen se construyó o se reutilizó")
	}
	if !strings.Contains(baseDescription(img), "golang:1.22.3@sha256:abc") {
		t.Fatalf("detalle = %q", baseDescription(img))
	}
}

func TestPsalmRunDirUsesStaging(t *testing.T) {
	if got := psalmRunDir("/cache/runs/1", ""); got != "/cache/runs/1" {
		t.Fatalf("sin staging = %q", got)
	}
	if got := psalmRunDir("/cache/runs/1", "/tmp/stage"); got != "/tmp/stage/psalm" {
		t.Fatalf("con staging = %q", got)
	}
}
