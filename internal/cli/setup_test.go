package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
)

func TestDecideSetupNonInteractive(t *testing.T) {
	dockerErr := &testDockerErr{}
	tests := []struct {
		name     string
		opts     setupOptions
		cfg      config.Config
		docker   error
		wantMode string
		wantErr  bool
	}{
		{"default con docker", setupOptions{NonInteractive: true}, config.Config{}, nil, "docker", false},
		{"default sin docker", setupOptions{NonInteractive: true}, config.Config{}, dockerErr, "global", false},
		{"flag docker", setupOptions{TrivyMode: "docker"}, config.Config{}, nil, "docker", false},
		{"flag docker sin daemon", setupOptions{TrivyMode: "docker"}, config.Config{}, dockerErr, "", true},
		{"flag global", setupOptions{TrivyMode: "global"}, config.Config{}, nil, "global", false},
		{"preferencia docker", setupOptions{}, config.Config{TrivyMode: "docker"}, nil, "docker", false},
		{"preferencia docker sin daemon", setupOptions{}, config.Config{TrivyMode: "docker"}, dockerErr, "", true},
		{"preferencia global pese a docker", setupOptions{}, config.Config{TrivyMode: "global"}, nil, "global", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			dec, err := decideSetup(tt.opts, tt.cfg, false, bufio.NewReader(strings.NewReader("")), &out, tt.docker)
			if tt.wantErr {
				if err == nil {
					t.Fatal("se esperaba error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if dec.Mode != tt.wantMode {
				t.Fatalf("modo = %q, want %q", dec.Mode, tt.wantMode)
			}
			if dec.Semgrep {
				t.Error("Semgrep no debe quedar habilitado sin pedirlo")
			}
		})
	}
}

func TestDecideSetupInteractiveChoosesGlobal(t *testing.T) {
	var out bytes.Buffer
	dec, err := decideSetup(
		setupOptions{}, config.Config{}, true,
		bufio.NewReader(strings.NewReader("2\nn\n")), &out, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Mode != "global" || dec.Semgrep {
		t.Fatalf("decisión = %+v", dec)
	}
	if !strings.Contains(out.String(), "Docker") {
		t.Errorf("no se mostró la pregunta: %q", out.String())
	}
}

func TestDecideSetupInteractiveEnablesSemgrep(t *testing.T) {
	var out bytes.Buffer
	dec, err := decideSetup(
		setupOptions{}, config.Config{TrivyMode: "global"}, true,
		bufio.NewReader(strings.NewReader("s\n")), &out, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Mode != "global" || !dec.Semgrep {
		t.Fatalf("decisión = %+v", dec)
	}
}

func TestDecideSetupWithoutDockerAsksConfirmation(t *testing.T) {
	var out bytes.Buffer
	dec, err := decideSetup(
		setupOptions{}, config.Config{}, true,
		bufio.NewReader(strings.NewReader("s\nn\n")), &out, &testDockerErr{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Mode != "global" {
		t.Fatalf("modo = %q", dec.Mode)
	}
	// Cancelar.
	_, err = decideSetup(
		setupOptions{}, config.Config{}, true,
		bufio.NewReader(strings.NewReader("n\n")), &out, &testDockerErr{},
	)
	if err == nil {
		t.Fatal("cancelar debe devolver error sin escribir configuración")
	}
}

func TestDecideSetupSemgrepEnable(t *testing.T) {
	var out bytes.Buffer
	dec, err := decideSetup(setupOptions{Semgrep: "enable"}, config.Config{TrivyMode: "global"}, false,
		bufio.NewReader(strings.NewReader("")), &out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Semgrep {
		t.Fatal("--semgrep enable no habilitó Semgrep")
	}
}

func TestDecideSetupSemgrepDisable(t *testing.T) {
	var out bytes.Buffer
	dec, err := decideSetup(setupOptions{Semgrep: "disable"}, config.Config{TrivyMode: "global", SemgrepEnabled: true}, false,
		bufio.NewReader(strings.NewReader("")), &out, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Semgrep {
		t.Fatal("Semgrep quedó habilitado pese a --semgrep disable")
	}
}

type testDockerErr struct{}

func (*testDockerErr) Error() string { return "daemon no responde" }
