package provision

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
)

func tarGz(t *testing.T, entries map[string]struct {
	body string
	mode int64
	typ  byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o755
		}
		hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(e.body)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Size = 0
			hdr.Linkname = e.body
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func serverFor(t *testing.T, payload []byte, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			hits.Add(1)
		}
		_, _ = w.Write(payload)
	}))
}

func testManifest(version, url, sha string) *manifest.Manifest {
	return &manifest.Manifest{
		Schema: 1,
		Engines: map[string]manifest.Engine{
			"trivy": {
				Version: version,
				Archives: map[string]manifest.Archive{
					manifest.PlatformKey(runtime.GOOS, runtime.GOARCH): {URL: url, SHA256: sha},
				},
			},
		},
	}
}

func testPaths(t *testing.T) platform.Paths {
	t.Helper()
	base := t.TempDir()
	return platform.Paths{
		ConfigDir: filepath.Join(base, "config"),
		DataDir:   filepath.Join(base, "data"),
		CacheDir:  filepath.Join(base, "cache"),
	}
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

const verScript = "#!/bin/sh\necho \"Version: 0.76.1\"\n"

func TestEnsureTrivyInstallsAndReuses(t *testing.T) {
	payload := tarGz(t, map[string]struct {
		body string
		mode int64
		typ  byte
	}{"trivy": {body: verScript, mode: 0o755}})
	var hits atomic.Int32
	srv := serverFor(t, payload, &hits)
	defer srv.Close()

	paths := testPaths(t)
	m := testManifest("0.76.1", srv.URL+"/trivy.tar.gz", sha(payload))
	opts := Options{Paths: paths, Manifest: m, HTTPClient: srv.Client()}

	first, err := EnsureTrivy(context.Background(), opts)
	if err != nil {
		t.Fatalf("EnsureTrivy: %v", err)
	}
	if !first.Installed || first.SHA256 != sha(payload) {
		t.Fatalf("resultado = %+v", first)
	}
	info, err := os.Stat(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("permisos = %o, want 755", info.Mode().Perm())
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("descargas = %d, want 1", got)
	}

	second, err := EnsureTrivy(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Installed {
		t.Error("la segunda llamada volvió a instalar")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("la segunda llamada descargó de nuevo (%d)", got)
	}
}

func TestEnsureTrivyRejectsBadChecksum(t *testing.T) {
	payload := tarGz(t, map[string]struct {
		body string
		mode int64
		typ  byte
	}{"trivy": {body: verScript}})
	srv := serverFor(t, payload, nil)
	defer srv.Close()

	paths := testPaths(t)
	m := testManifest("0.76.1", srv.URL+"/trivy.tar.gz", "0000000000000000000000000000000000000000000000000000000000000000")
	_, err := EnsureTrivy(context.Background(), Options{Paths: paths, Manifest: m, HTTPClient: srv.Client()})
	if err == nil {
		t.Fatal("se aceptó un checksum inválido")
	}
	if _, statErr := os.Stat(filepath.Join(paths.EngineDir("trivy", "0.76.1"), "trivy")); !os.IsNotExist(statErr) {
		t.Fatal("quedó un binario tras un checksum inválido")
	}
}

func TestEnsureTrivyRejectsUnsafeArchive(t *testing.T) {
	cases := map[string]map[string]struct {
		body string
		mode int64
		typ  byte
	}{
		"path traversal": {"../trivy": {body: verScript}},
		"absoluto":       {"/usr/local/bin/trivy": {body: verScript}},
		"enlace":         {"trivy": {body: "/bin/sh", typ: tar.TypeSymlink}},
		"sin binario":    {"otro": {body: "x"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			payload := tarGz(t, entries)
			srv := serverFor(t, payload, nil)
			defer srv.Close()
			paths := testPaths(t)
			m := testManifest("0.76.1", srv.URL+"/a.tar.gz", sha(payload))
			_, err := EnsureTrivy(context.Background(), Options{Paths: paths, Manifest: m, HTTPClient: srv.Client()})
			if err == nil {
				t.Fatal("se aceptó un archivo inseguro")
			}
		})
	}
}

func TestEnsureTrivyRejectsWrongVersionBinary(t *testing.T) {
	payload := tarGz(t, map[string]struct {
		body string
		mode int64
		typ  byte
	}{"trivy": {body: "#!/bin/sh\necho \"Version: 9.9.9\"\n"}})
	srv := serverFor(t, payload, nil)
	defer srv.Close()
	paths := testPaths(t)
	m := testManifest("0.76.1", srv.URL+"/a.tar.gz", sha(payload))
	_, err := EnsureTrivy(context.Background(), Options{Paths: paths, Manifest: m, HTTPClient: srv.Client()})
	if err == nil {
		t.Fatal("se aceptó un binario con versión distinta")
	}
}

func TestEnsureTrivyRejectsOversizeDownload(t *testing.T) {
	payload := tarGz(t, map[string]struct {
		body string
		mode int64
		typ  byte
	}{"trivy": {body: verScript}})
	srv := serverFor(t, payload, nil)
	defer srv.Close()
	paths := testPaths(t)
	m := testManifest("0.76.1", srv.URL+"/a.tar.gz", sha(payload))
	_, err := EnsureTrivy(context.Background(), Options{Paths: paths, Manifest: m, HTTPClient: srv.Client(), MaxDownload: 10})
	if err == nil {
		t.Fatal("se aceptó una descarga que supera el tope")
	}
}

func TestEnsureTrivyConcurrentInstallsOnce(t *testing.T) {
	payload := tarGz(t, map[string]struct {
		body string
		mode int64
		typ  byte
	}{"trivy": {body: verScript}})
	var hits atomic.Int32
	srv := serverFor(t, payload, &hits)
	defer srv.Close()
	paths := testPaths(t)
	m := testManifest("0.76.1", srv.URL+"/a.tar.gz", sha(payload))

	done := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, err := EnsureTrivy(context.Background(), Options{Paths: paths, Manifest: m, HTTPClient: srv.Client()})
			done <- err
		}()
	}
	for i := 0; i < 3; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("instalación concurrente: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timeout esperando instalaciones concurrentes")
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("descargas = %d, want 1", got)
	}
}
