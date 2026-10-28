package provision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/manifest"
	banditassets "github.com/CGCServicesSpA/cgc-scan/manifest/bandit"
	eslintassets "github.com/CGCServicesSpA/cgc-scan/manifest/eslint"
)

// AdapterInstall es el resultado de aprovisionar una herramienta de adaptador.
type AdapterInstall struct {
	ID        string
	Version   string
	Dir       string
	Binary    string // ejecutable directo o script de ESLint
	Node      string // intérprete Node (solo ESLint)
	PHP       string
	Python    string
	Installed bool
}

// AdapterOptions configura el aprovisionamiento de adaptadores.
type AdapterOptions struct {
	Paths         platform.Paths
	Manifest      *manifest.Manifest
	HTTPClient    *http.Client
	GOOS          string
	GOARCH        string
	Offline       bool
	NoAutoInstall bool
	MaxDownload   int64
}

// EnsureAdapter instala o reutiliza una herramienta de adaptador con las
// mismas garantías que Trivy: versión y hash fijados, sin scripts y sin
// escribir en el proyecto (D-01).
func EnsureAdapter(ctx context.Context, opts AdapterOptions, id string) (AdapterInstall, error) {
	if opts.Manifest == nil {
		return AdapterInstall{}, errors.New("provisión: manifiesto ausente")
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Minute}
	}
	if opts.MaxDownload == 0 {
		opts.MaxDownload = DefaultMaxDownload
	}
	spec, err := opts.Manifest.Adapter(id)
	if err != nil {
		return AdapterInstall{}, err
	}

	if spec.Mode == "library" {
		return AdapterInstall{ID: id, Version: spec.Version}, nil
	}

	dir := opts.Paths.EngineDir(id, spec.Version)
	lock, err := platform.Acquire(ctx, filepath.Join(opts.Paths.LocksDir(), "engine-"+id+".lock"), false, 10*time.Minute)
	if err != nil {
		return AdapterInstall{}, err
	}
	defer func() { _ = lock.Release() }()

	install := AdapterInstall{ID: id, Version: spec.Version, Dir: dir}
	switch spec.Mode {
	case "npm":
		return installESLint(ctx, opts, spec, install)
	case "phar":
		return installPsalm(ctx, opts, spec, install)
	case "binary":
		return installCargoAudit(ctx, opts, spec, install)
	case "venv":
		return installBandit(ctx, opts, spec, install)
	}
	return AdapterInstall{}, fmt.Errorf("modo de adaptador no soportado: %q", spec.Mode)
}

// VerifyAdapter comprueba que una herramienta instalada responde con la
// versión fijada.
func VerifyAdapter(ctx context.Context, in AdapterInstall) (bool, string) {
	switch in.ID {
	case "eslint":
		node, err := exec.LookPath("node")
		if err != nil {
			return false, "node no está en PATH"
		}
		bin := filepath.Join(in.Dir, "node_modules", "eslint", "bin", "eslint.js")
		return runVersionContains(ctx, node, []string{bin, "--version"}, in.Version)
	case "psalm":
		php, err := exec.LookPath("php")
		if err != nil {
			return false, "php no está en PATH"
		}
		bin := filepath.Join(in.Dir, "psalm.phar")
		return runVersionContains(ctx, php, []string{bin, "--version"}, in.Version)
	case "cargo-audit":
		bin := filepath.Join(in.Dir, "cargo-audit")
		return runVersionContains(ctx, bin, []string{"--version"}, in.Version)
	case "bandit":
		bin := filepath.Join(in.Dir, "venv", "bin", "bandit")
		return runVersionContains(ctx, bin, []string{"--version"}, in.Version)
	case "govulncheck":
		return true, "biblioteca enlazada"
	}
	return false, "adaptador desconocido"
}

func runVersionContains(ctx context.Context, bin string, args []string, want string) (bool, string) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// #nosec G204 -- bin es una ruta instalada por la CLI o un intérprete de PATH.
	out, err := exec.CommandContext(cctx, bin, args...).CombinedOutput()
	if err != nil {
		return false, fmt.Sprintf("ejecutar %s: %v", filepath.Base(bin), err)
	}
	text := strings.TrimSpace(string(out))
	if strings.Contains(text, want) {
		return true, text
	}
	return false, "versión inesperada: " + firstLine(text)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func installESLint(ctx context.Context, opts AdapterOptions, spec manifest.Adapter, in AdapterInstall) (AdapterInstall, error) {
	node, nodeErr := exec.LookPath("node")
	npm, npmErr := exec.LookPath("npm")
	if nodeErr != nil || npmErr != nil {
		return in, fmt.Errorf("eslint requiere Node y npm en PATH: %w", errors.Join(nodeErr, npmErr))
	}
	in.Node = node
	if ok, _ := VerifyAdapter(ctx, in); ok {
		return in, nil
	}
	if opts.Offline || opts.NoAutoInstall {
		return in, fmt.Errorf("eslint %s no está instalado y %s prohíbe descargarlo", spec.Version, reasonFor(opts))
	}
	if err := os.MkdirAll(in.Dir, 0o700); err != nil {
		return in, err
	}
	home := opts.Paths.SandboxHome("eslint")
	if err := platform.EnsurePrivateDir(home); err != nil {
		return in, err
	}
	if err := platform.EnsurePrivateDir(filepath.Join(opts.Paths.CacheDir, "npm")); err != nil {
		return in, err
	}
	lockSum := sha256.Sum256(eslintassets.LockJSON)
	if got := hex.EncodeToString(lockSum[:]); got != spec.LockfileSHA256 {
		return in, fmt.Errorf("el package-lock embebido no coincide con el manifiesto (%s != %s)", got, spec.LockfileSHA256)
	}
	if err := platform.WriteFileAtomic(filepath.Join(in.Dir, "package.json"), eslintassets.PackageJSON, 0o600); err != nil {
		return in, err
	}
	if err := platform.WriteFileAtomic(filepath.Join(in.Dir, "package-lock.json"), eslintassets.LockJSON, 0o600); err != nil {
		return in, err
	}
	if err := platform.WriteFileAtomic(filepath.Join(in.Dir, "cgc-eslint.config.mjs"), eslintassets.Config, 0o600); err != nil {
		return in, err
	}
	env := append(os.Environ(),
		"HOME="+home,
		"npm_config_cache="+filepath.Join(opts.Paths.CacheDir, "npm"),
		"PATH="+filepath.Dir(node)+":"+os.Getenv("PATH"),
		"npm_config_audit=false",
		"npm_config_fund=false",
	)
	// #nosec G204 -- npm es una ruta de PATH y los argumentos son fijos.
	cmd := exec.CommandContext(ctx, npm, "ci", "--ignore-scripts", "--no-audit", "--no-fund")
	cmd.Dir = in.Dir
	cmd.Env = env
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return in, fmt.Errorf("instalar ESLint con npm ci: %w", err)
	}
	if ok, detail := VerifyAdapter(ctx, in); !ok {
		return in, fmt.Errorf("eslint instalado no responde: %s", detail)
	}
	in.Installed = true
	return in, nil
}

func installPsalm(ctx context.Context, opts AdapterOptions, spec manifest.Adapter, in AdapterInstall) (AdapterInstall, error) {
	php, err := exec.LookPath("php")
	if err != nil {
		return in, errors.New("psalm requiere PHP en PATH")
	}
	in.PHP = php
	if ok, _ := VerifyAdapter(ctx, in); ok {
		return in, nil
	}
	if opts.Offline || opts.NoAutoInstall {
		return in, fmt.Errorf("psalm %s no está instalado y %s prohíbe descargarlo", spec.Version, reasonFor(opts))
	}
	if err := os.MkdirAll(in.Dir, 0o700); err != nil {
		return in, err
	}
	tmp, err := os.CreateTemp(in.Dir, ".psalm-*")
	if err != nil {
		return in, err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := downloadVerified(ctx, opts.HTTPClient, spec.URL, spec.SHA256, opts.MaxDownload, tmp); err != nil {
		_ = tmp.Close()
		return in, err
	}
	if err := tmp.Close(); err != nil {
		return in, err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil { //nolint:gosec // el phar debe ser ejecutable
		return in, err
	}
	final := filepath.Join(in.Dir, "psalm.phar")
	if err := os.Rename(tmpPath, final); err != nil {
		return in, err
	}
	if ok, detail := VerifyAdapter(ctx, in); !ok {
		return in, fmt.Errorf("psalm instalado no responde: %s", detail)
	}
	in.Installed = true
	return in, nil
}

func installCargoAudit(ctx context.Context, opts AdapterOptions, spec manifest.Adapter, in AdapterInstall) (AdapterInstall, error) {
	if ok, _ := VerifyAdapter(ctx, in); ok {
		return in, nil
	}
	if opts.Offline || opts.NoAutoInstall {
		return in, fmt.Errorf("cargo-audit %s no está instalado y %s prohíbe descargarlo", spec.Version, reasonFor(opts))
	}
	ar, err := spec.Archive(opts.GOOS, opts.GOARCH)
	if err != nil {
		return in, err
	}
	if err := os.MkdirAll(in.Dir, 0o700); err != nil {
		return in, err
	}
	tmpArchive, err := os.CreateTemp(in.Dir, ".cargo-audit-*")
	if err != nil {
		return in, err
	}
	tmpArchivePath := tmpArchive.Name()
	defer func() { _ = os.Remove(tmpArchivePath) }()
	if _, err := downloadVerified(ctx, opts.HTTPClient, ar.URL, ar.SHA256, opts.MaxDownload, tmpArchive); err != nil {
		_ = tmpArchive.Close()
		return in, err
	}
	if err := tmpArchive.Close(); err != nil {
		return in, err
	}
	binTmp, err := os.CreateTemp(in.Dir, ".cargo-audit-bin-*")
	if err != nil {
		return in, err
	}
	binTmpPath := binTmp.Name()
	defer func() { _ = os.Remove(binTmpPath) }()
	if err := extractBinary(tmpArchivePath, "cargo-audit", binTmp); err != nil {
		_ = binTmp.Close()
		return in, err
	}
	if err := binTmp.Close(); err != nil {
		return in, err
	}
	if err := os.Chmod(binTmpPath, 0o755); err != nil { //nolint:gosec // el binario debe ser ejecutable
		return in, err
	}
	if err := os.Rename(binTmpPath, filepath.Join(in.Dir, "cargo-audit")); err != nil {
		return in, err
	}
	if ok, detail := VerifyAdapter(ctx, in); !ok {
		return in, fmt.Errorf("cargo-audit instalado no responde: %s", detail)
	}
	in.Installed = true
	return in, nil
}

func installBandit(ctx context.Context, opts AdapterOptions, spec manifest.Adapter, in AdapterInstall) (AdapterInstall, error) {
	python, err := exec.LookPath("python3")
	if err != nil {
		return in, errors.New("bandit requiere python3 en PATH")
	}
	in.Python = python
	if ok, _ := VerifyAdapter(ctx, in); ok {
		return in, nil
	}
	if opts.Offline || opts.NoAutoInstall {
		return in, fmt.Errorf("bandit %s no está instalado y %s prohíbe descargarlo", spec.Version, reasonFor(opts))
	}
	sum := sha256.Sum256(banditassets.Requirements)
	if got := hex.EncodeToString(sum[:]); got != spec.RequirementsSHA256 {
		return in, fmt.Errorf("las dependencias embebidas de Bandit no coinciden con el manifiesto")
	}
	if err := os.MkdirAll(in.Dir, 0o700); err != nil {
		return in, err
	}
	reqPath := filepath.Join(in.Dir, "requirements.txt")
	if err := platform.WriteFileAtomic(reqPath, banditassets.Requirements, 0o600); err != nil {
		return in, err
	}
	venv := filepath.Join(in.Dir, "venv")
	if _, err := os.Stat(filepath.Join(venv, "bin", "python")); err != nil {
		cmd := exec.CommandContext(ctx, python, "-m", "venv", venv) //nolint:gosec // python proviene de PATH
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return in, fmt.Errorf("crear entorno de Bandit: %w", err)
		}
	}
	home := opts.Paths.SandboxHome("bandit")
	if err := platform.EnsurePrivateDir(home); err != nil {
		return in, err
	}
	pip := filepath.Join(venv, "bin", "pip")
	cmd := exec.CommandContext(ctx, pip, "install", //nolint:gosec // pip del entorno recién creado
		"--require-hashes", "--only-binary=:all:", "--no-cache-dir", "--disable-pip-version-check",
		"-r", reqPath)
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return in, fmt.Errorf("instalar Bandit con hashes: %w", err)
	}
	if ok, detail := VerifyAdapter(ctx, in); !ok {
		return in, fmt.Errorf("bandit instalado no responde: %s", detail)
	}
	in.Installed = true
	return in, nil
}

func reasonFor(opts AdapterOptions) string {
	if opts.Offline {
		return "--offline"
	}
	return "--no-auto-install"
}
