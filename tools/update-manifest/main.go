// Command update-manifest regenera manifest/trust.json desde el release real
// de Trivy: descarga los artefactos, verifica la firma sin clave de Sigstore y
// los checksums publicados, resuelve el digest de la imagen y escribe los
// hashes. Corre en CI; nunca en tiempo de ejecución de la CLI (ADR-07).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Mirror de la estructura que se escribe; se mantiene independiente de
// internal/manifest para que el tool pueda regenerar un manifiesto roto.
type manifest struct {
	Schema  int               `json:"schema"`
	Engines map[string]engine `json:"engines"`
}

type engine struct {
	Version  string             `json:"version"`
	Image    string             `json:"image,omitempty"`
	Archives map[string]archive `json:"archives,omitempty"`
}

type archive struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

var platforms = map[string]string{
	"linux-amd64":  "Linux-64bit",
	"linux-arm64":  "Linux-ARM64",
	"darwin-amd64": "macOS-64bit",
	"darwin-arm64": "macOS-ARM64",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "update-manifest: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		version       = flag.String("version", "0.76.1", "versión de Trivy (sin la v)")
		repository    = flag.String("repo", "aquasecurity/trivy", "repositorio GitHub del motor")
		imageRepo     = flag.String("image-repo", "aquasecurity/trivy", "repositorio de la imagen en GHCR")
		out           = flag.String("out", "manifest/trust.json", "archivo de salida")
		cosign        = flag.String("cosign", "cosign", "binario de cosign")
		skipSignature = flag.Bool("skip-signature", false, "no verificar la firma (solo desarrollo local)")
		timeout       = flag.Duration("timeout", 5*time.Minute, "timeout de red")
	)
	flag.Parse()

	if !strings.HasPrefix(*version, "v") {
		*version = "v" + *version
	}
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", *repository, *version)
	client := &http.Client{Timeout: *timeout}
	dir, err := os.MkdirTemp("", "cgc-manifest-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	checksumsPath := filepath.Join(dir, "checksums.txt")
	checksumsURL := fmt.Sprintf("%s/trivy_%s_checksums.txt", base, strings.TrimPrefix(*version, "v"))
	if err := download(client, checksumsURL, checksumsPath); err != nil {
		return fmt.Errorf("descargar checksums: %w", err)
	}

	bundleURL := checksumsURL + ".sigstore.json"
	bundlePath := checksumsPath + ".sigstore.json"
	if err := download(client, bundleURL, bundlePath); err != nil {
		return fmt.Errorf("descargar bundle de firma: %w", err)
	}
	if *skipSignature {
		fmt.Fprintln(os.Stderr, "AVISO: firma no verificada por --skip-signature")
	} else {
		if err := verifySignature(*cosign, checksumsPath, bundlePath); err != nil {
			return err
		}
	}

	checksums, err := parseChecksums(checksumsPath)
	if err != nil {
		return err
	}

	eng := engine{
		Version:  strings.TrimPrefix(*version, "v"),
		Archives: make(map[string]archive, len(platforms)),
	}
	keys := make([]string, 0, len(platforms))
	for k := range platforms {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		suffix := fmt.Sprintf("trivy_%s_%s.tar.gz", strings.TrimPrefix(*version, "v"), platforms[key])
		want, ok := checksums[suffix]
		if !ok {
			return fmt.Errorf("el release no publica %s", suffix)
		}
		url := base + "/" + suffix
		path := filepath.Join(dir, suffix)
		if err := download(client, url, path); err != nil {
			return fmt.Errorf("descargar %s: %w", suffix, err)
		}
		got, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s: sha256 %s no coincide con el publicado %s", suffix, got, want)
		}
		eng.Archives[key] = archive{URL: url, SHA256: got}
		fmt.Fprintf(os.Stderr, "verificado %s (%s)\n", suffix, got[:12])
	}

	digest, err := resolveImageDigest(client, *imageRepo, strings.TrimPrefix(*version, "v"))
	if err != nil {
		return fmt.Errorf("resolver digest de la imagen: %w", err)
	}
	eng.Image = fmt.Sprintf("ghcr.io/%s@%s", *imageRepo, digest)
	fmt.Fprintf(os.Stderr, "imagen %s\n", eng.Image)

	m := manifest{Schema: 1, Engines: map[string]engine{"trivy": eng}}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil { //nolint:gosec // manifiesto público del repositorio
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // manifiesto público, sin secretos
		return err
	}
	fmt.Fprintf(os.Stderr, "manifiesto escrito en %s\n", *out)
	return nil
}

func verifySignature(cosign, blob, bundle string) error {
	cmd := exec.Command(cosign, "verify-blob", //nolint:gosec // ruta de cosign configurada en CI
		"--bundle", bundle,
		"--certificate-identity-regexp", `^https://github.com/aquasecurity/trivy/`,
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		blob,
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("la firma de checksums no es válida: %w", err)
	}
	return nil
}

func download(client *http.Client, url, path string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return f.Sync()
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func parseChecksums(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		out[strings.TrimPrefix(fields[1], "*")] = fields[0]
	}
	if len(out) == 0 {
		return nil, errors.New("checksums.txt no contiene hashes")
	}
	return out, nil
}

// resolveImageDigest consulta el registro de GHCR sin credenciales de usuario.
func resolveImageDigest(client *http.Client, repo, tag string) (string, error) {
	tokenResp, err := client.Get("https://ghcr.io/token?scope=repository:" + repo + ":pull")
	if err != nil {
		return "", err
	}
	defer func() { _ = tokenResp.Body.Close() }()
	if tokenResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token de GHCR: HTTP %d", tokenResp.StatusCode)
	}
	var token struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&token); err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, "https://ghcr.io/v2/"+repo+"/manifests/"+tag, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("manifiesto de %s:%s: HTTP %d", repo, tag, resp.StatusCode)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("digest inesperado %q", digest)
	}
	return digest, nil
}
