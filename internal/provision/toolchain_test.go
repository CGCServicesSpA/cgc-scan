package provision

import (
	"context"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/toolchain"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

func TestEnsureToolchainImageRejectsInvalidVersion(t *testing.T) {
	ms, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ms.Adapter("govulncheck")
	if err != nil {
		t.Fatal(err)
	}
	_, err = EnsureToolchainImage(context.Background(), ToolchainOptions{DockerBin: "docker"},
		toolchain.Spec{Language: discovery.Go, Version: "1.22; rm -rf /"}, spec)
	if err == nil {
		t.Fatal("se aceptó una versión con texto arbitrario")
	}
}

func TestEnsureToolchainImageRejectsUnknownLanguage(t *testing.T) {
	ms, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := ms.Adapter("bandit")
	if _, err := EnsureToolchainImage(context.Background(), ToolchainOptions{}, toolchain.Spec{}, spec); err == nil {
		t.Fatal("se aceptó una unidad sin lenguaje")
	}
}

func TestVersionish(t *testing.T) {
	for _, v := range []string{"1", "1.22", "1.22.3", "3.12.1"} {
		if !versionish(v) {
			t.Errorf("%q debería aceptarse", v)
		}
	}
	for _, v := range []string{"", "1..2", "1.2 ", "v1.2", "1.2\n"} {
		if versionish(v) {
			t.Errorf("%q no debería aceptarse", v)
		}
	}
}
