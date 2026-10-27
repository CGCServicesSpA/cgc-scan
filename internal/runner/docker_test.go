package runner

import (
	"strings"
	"testing"
)

func TestDockerScanArgsAreHardened(t *testing.T) {
	d := &Docker{Image: "ghcr.io/x@sha256:abc", Volume: "vol"}
	args, err := d.buildArgs(Invocation{
		Engine: "trivy", ProjectRO: "/repo", Dir: "/repo/svc/api",
		Args: []string{"fs", "."},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--network none",
		"--read-only",
		"--tmpfs /tmp",
		"--cap-drop ALL",
		"--security-opt no-new-privileges",
		"--pids-limit 512",
		"--memory 2g",
		"-v /repo:/src:ro",
		"-w /src/svc/api",
		"-v vol:/cache",
		"ghcr.io/x@sha256:abc fs .",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("faltan %q en: %s", want, joined)
		}
	}
	if strings.Contains(joined, " --user ") {
		t.Error("no debe pasarse --user: el volumen del daemon es de root (ADR-13)")
	}
}

func TestDockerUpdaterHasNetworkAndNoProject(t *testing.T) {
	d := &Docker{Image: "img@sha256:abc", Volume: "vol"}
	args, err := d.buildArgs(Invocation{
		Engine: "trivy", Args: []string{"fs", "--download-db-only"},
		AllowNetwork: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--network") {
		t.Error("el actualizador no debe deshabilitar la red")
	}
	if strings.Contains(joined, "/src") {
		t.Error("el actualizador no debe montar el proyecto")
	}
	if !strings.Contains(joined, "-v vol:/cache") {
		t.Error("el actualizador debe montar el volumen de caché")
	}
}

func TestDockerRejectsWorkdirOutsideProject(t *testing.T) {
	d := &Docker{Image: "img@sha256:abc", Volume: "vol"}
	if _, err := d.buildArgs(Invocation{ProjectRO: "/repo", Dir: "/otro"}); err == nil {
		t.Fatal("se aceptó un directorio fuera del proyecto")
	}
}

func TestDockerRequiresDigest(t *testing.T) {
	d := &Docker{Image: "ghcr.io/x:latest", Volume: "vol"}
	// buildArgs no valida el digest, pero Run sí.
	if _, err := d.Run(t.Context(), Invocation{}); err == nil {
		t.Fatal("se aceptó una imagen sin digest")
	}
}

func TestVolumeNameIsPerUser(t *testing.T) {
	if got := VolumeName(501); got != "cgc-scan-trivy-cache-501" {
		t.Fatalf("nombre = %q", got)
	}
	if VolumeName(501) == VolumeName(502) {
		t.Fatal("dos usuarios comparten volumen")
	}
}

func TestResolveMatrix(t *testing.T) {
	dockerErr := &DockerError{Code: "docker_unavailable", Message: "sin daemon"}
	tests := []struct {
		name    string
		in      ResolveRequest
		mode    string
		origin  string
		wantErr bool
	}{
		{"sin preferencia con docker", ResolveRequest{DockerOK: true}, "docker", "default", false},
		{"sin preferencia sin docker", ResolveRequest{DockerOK: false, DockerErr: dockerErr}, "global", "default", false},
		{"preferencia docker con docker", ResolveRequest{Stored: "docker", DockerOK: true}, "docker", "setup", false},
		{"preferencia docker sin docker", ResolveRequest{Stored: "docker", DockerOK: false, DockerErr: dockerErr}, "", "", true},
		{"flag docker sin docker", ResolveRequest{Explicit: "docker", DockerOK: false, DockerErr: dockerErr}, "", "", true},
		{"flag global sin docker", ResolveRequest{Explicit: "global", DockerOK: false, DockerErr: dockerErr}, "global", "flag", false},
		{"flag global pisa preferencia docker", ResolveRequest{Explicit: "global", Stored: "docker", DockerOK: true}, "global", "flag", false},
		{"flag docker pisa preferencia global", ResolveRequest{Explicit: "docker", Stored: "global", DockerOK: true}, "docker", "flag", false},
		{"modalidad desconocida", ResolveRequest{Explicit: "podman", DockerOK: true}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("se esperaba error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Mode != tt.mode || got.Origin != tt.origin {
				t.Fatalf("resultado = %+v, want %s/%s", got, tt.mode, tt.origin)
			}
			if tt.in.Explicit == "" && tt.in.Stored == "" && !tt.in.DockerOK && got.FallbackReason == "" {
				t.Error("falta la causa del fallback")
			}
		})
	}
}

func TestRemoteEndpoint(t *testing.T) {
	for _, h := range []string{"tcp://1.2.3.4:2376", "ssh://user@host", "https://x"} {
		if !remoteEndpoint(h) {
			t.Errorf("%q debería ser remoto", h)
		}
	}
	for _, h := range []string{"unix:///var/run/docker.sock", "npipe:////./pipe/docker_engine", ""} {
		if remoteEndpoint(h) {
			t.Errorf("%q no debería ser remoto", h)
		}
	}
}
