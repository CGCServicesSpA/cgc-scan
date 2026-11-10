// Package govulncheck implementa el adaptador de Go usando la biblioteca
// golang.org/x/vuln/scan y una base local (ADR-14, P-10).
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/vuln/scan"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// ID identifica el motor.
const ID = "govulncheck"

// ContainerDBDir es la ruta donde el runner monta la base local dentro de la
// imagen de toolchain.
const ContainerDBDir = "/cgc-vulndb"

// Adapter ejecuta govulncheck en modo fuente.
type Adapter struct {
	Version  string
	DBDir    string
	Root     string
	Masker   *masking.Masker
	GoBinary string
	GoEnv    map[string]string
	// ContainerFor resuelve la imagen de toolchain de una unidad. Si es nil o
	// devuelve nil, el adaptador usa el binario Go del host.
	ContainerFor func(discovery.Unit) *adapter.Container
}

// New construye el adaptador y resuelve el entorno de Go.
func New(root, dbDir, goBinary string, m *masking.Masker) *Adapter {
	a := &Adapter{Version: "1.9.0", Root: root, DBDir: dbDir, Masker: m, GoBinary: goBinary}
	a.GoEnv = goEnvironment(goBinary)
	return a
}

func (a *Adapter) ID() string { return ID }

// Applies cubre unidades Go con módulo.
func (a *Adapter) Applies(u discovery.Unit) bool {
	return hasLanguage(u, discovery.Go) && u.Kind != "repository"
}

// AcceptExit acepta el código 3 con el que el CLI de govulncheck señala
// vulnerabilidades encontradas. El binario en contenedor no usa el camino de
// la biblioteca, así que este contrato es necesario.
func (a *Adapter) AcceptExit(code int) bool {
	return code == 0 || code == 3
}

// Requirements comprueba toolchain, módulo y base local.
func (a *Adapter) Requirements(_ context.Context, u discovery.Unit) []adapter.Requirement {
	var reqs []adapter.Requirement
	if a.container(u) == nil && a.GoBinary == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "toolchain", Name: "go", Detail: "no está en PATH", Missing: true})
	}
	if !hasManifest(u, "go.mod") && u.Kind != "directory" {
		reqs = append(reqs, adapter.Requirement{Kind: "module", Name: "go.mod", Detail: "la unidad no tiene módulo", Missing: true})
	}
	if a.DBDir == "" {
		reqs = append(reqs, adapter.Requirement{Kind: "database", Name: "go-vulndb", Detail: "base local no preparada", Missing: true})
	}
	return reqs
}

// Invocations devuelve una ejecución en proceso con la biblioteca o, si hay
// imagen de toolchain, una ejecución dentro del contenedor del lenguaje.
func (a *Adapter) Invocations(u discovery.Unit, _ plan.Plan) ([]runner.Invocation, error) {
	unitDir := filepath.Join(a.Root, u.Path)
	if c := a.container(u); c != nil {
		return []runner.Invocation{{
			Engine:       ID,
			Image:        c.Image,
			ProjectRO:    a.Root,
			Dir:          unitDir,
			Mounts:       c.Mounts,
			AllowNetwork: !c.Offline,
			Args: []string{
				"govulncheck",
				"-db", "file://" + ContainerDBDir,
				"-mode=source", "-scan=symbol", "-format=json",
				"./...",
			},
			Env: map[string]string{
				// El toolchain debe ser el de la imagen: descargar otro
				// contradiría la versión detectada del proyecto.
				"GOTOOLCHAIN": "local",
				"GOPATH":      "/go",
				"GOMODCACHE":  filepath.ToSlash(c.CacheDir) + "/go-mod",
				"GOCACHE":     filepath.ToSlash(c.CacheDir) + "/go-build",
			},
			Timeout: 15 * time.Minute,
		}}, nil
	}
	if a.GoBinary == "" {
		return nil, fmt.Errorf("govulncheck: falta el toolchain Go")
	}
	args := []string{
		"-C", unitDir,
		"-db", "file://" + a.DBDir,
		"-mode=source", "-scan=symbol", "-format=json",
		"./...",
	}
	inv := runner.Invocation{
		Engine:  ID,
		Timeout: 10 * time.Minute,
		Env:     a.env(),
	}
	inv.Local = func(ctx context.Context, env []string) (runner.Result, error) {
		return runLibrary(ctx, args, env)
	}
	return []runner.Invocation{inv}, nil
}

// container resuelve la imagen de toolchain de la unidad, si existe.
func (a *Adapter) container(u discovery.Unit) *adapter.Container {
	if a.ContainerFor == nil {
		return nil
	}
	return a.ContainerFor(u)
}

func runLibrary(ctx context.Context, args, env []string) (runner.Result, error) {
	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, args...)
	cmd.Env = env
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	start := time.Now()
	startErr := cmd.Start()
	if startErr != nil {
		return runner.Result{Stderr: stderr.Bytes()}, startErr
	}
	waitErr := cmd.Wait()
	res := runner.Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: time.Since(start),
		ExitCode: 0,
	}
	// Un error de Wait puede significar "hallazgos" (código 3). Si la salida
	// contiene objetos osv/finding, el parser decide; si solo hay config, el
	// análisis no llegó a ejecutarse y se propaga el fallo.
	if waitErr != nil {
		out := stdout.Bytes()
		hasResults := bytes.Contains(out, []byte(`"finding"`)) || bytes.Contains(out, []byte(`"osv"`))
		if !hasResults {
			res.ExitCode = 1
			return res, fmt.Errorf("govulncheck: %w: %s", waitErr, firstLine(stderr.String()))
		}
	}
	return res, nil
}

// Report es el flujo de objetos JSON de govulncheck.
type streamObject struct {
	Config  json.RawMessage `json:"config"`
	OSV     *OSV            `json:"osv"`
	Finding *Finding        `json:"finding"`
	SBOM    json.RawMessage `json:"SBOM"`
}

// OSV es la definición de una vulnerabilidad.
type OSV struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

// Finding es un hallazgo con su traza.
type Finding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
	Trace        []struct {
		Module   string `json:"module"`
		Version  string `json:"version"`
		Package  string `json:"package"`
		Function string `json:"function"`
		Position struct {
			Filename string `json:"filename"`
			Line     int    `json:"line"`
		} `json:"position"`
	} `json:"trace"`
}

// Acc := keeps the parser tolerant to unknown objects and partial output.
type Parsed = adapter.Parsed

// Parse interpreta el flujo JSON. Un objeto truncado al final no invalida los
// objetos completos anteriores, pero se registra como diagnóstico.
func (a *Adapter) Parse(raw []byte) (Parsed, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var (
		osvs     = map[string]*OSV{}
		findings []Finding
		diags    []adapter.Diagnostic
	)
	for {
		var obj streamObject
		if err := dec.Decode(&obj); err != nil {
			if err == io.EOF {
				break
			}
			if len(osvs) == 0 && len(findings) == 0 {
				return Parsed{}, fmt.Errorf("salida de govulncheck inválida: %w", err)
			}
			diags = append(diags, adapter.Diagnostic{Engine: ID, Message: "salida truncada: " + err.Error()})
			break
		}
		if obj.OSV != nil {
			osvs[obj.OSV.ID] = obj.OSV
		}
		if obj.Finding != nil {
			findings = append(findings, *obj.Finding)
		}
	}
	out := make([]normalize.Finding, 0, len(findings))
	for _, f := range findings {
		out = append(out, a.toFinding(f, osvs[f.OSV]))
	}
	normalize.SortFindings(out)
	return Parsed{Findings: out, Diagnostics: diags}, nil
}

func (a *Adapter) toFinding(f Finding, osv *OSV) normalize.Finding {
	module, version := "", ""
	path := "go.mod"
	if len(f.Trace) > 0 {
		module, version = f.Trace[0].Module, f.Trace[0].Version
		if f.Trace[0].Position.Filename != "" {
			path = a.relative(f.Trace[0].Position.Filename)
		}
	}
	severity := normalize.SeverityUnknown
	if osv != nil {
		severity = normalize.NormalizeSeverity(ID, osv.DatabaseSpecific.Severity)
	}
	finding := normalize.Finding{
		Kind:  normalize.KindVulnerability,
		Title: firstNonEmpty(summaryOf(osv), f.OSV, "vulnerabilidad de Go"),
		Severity: normalize.SeverityInfo{
			Original: severityOf(osv), Normalized: severity, Source: ID,
		},
		Sources:  []normalize.SourceRef{{Engine: ID, Version: a.Version}},
		Evidence: normalize.Evidence{Redacted: true},
		Policy:   normalize.FindingPolicy{Status: "active"},
	}
	if osv != nil {
		if osv.Details != "" {
			finding.Descriptions = append(finding.Descriptions, normalize.Description{Text: a.Masker.Redact(osv.Details, nil), Source: ID})
		}
		for _, ref := range osv.References {
			if ref.URL != "" {
				finding.References = append(finding.References, masking.Sanitize(ref.URL))
			}
		}
	}
	if len(f.Trace) > 0 && f.Trace[0].Function != "" {
		finding.Descriptions = append(finding.Descriptions, normalize.Description{
			Text:   "Símbolo alcanzable: " + masking.Sanitize(f.Trace[0].Package+"."+f.Trace[0].Function),
			Source: "govulncheck",
		})
	}
	finding.AddID("GO", f.OSV)
	if osv != nil {
		for _, alias := range osv.Aliases {
			finding.AddID(idType(alias), alias)
		}
	}
	finding.Package = &normalize.PackageRef{Ecosystem: "Go", Name: module, Version: version}
	if f.FixedVersion != "" {
		fixed := f.FixedVersion
		finding.Package.FixedVersion = &fixed
		finding.Remediation = []normalize.Remediation{{
			Description: fmt.Sprintf("Actualizar %s a %s o superior", module, f.FixedVersion),
			Source:      "advisory",
		}}
	}
	reachable := true
	finding.Priority = &normalize.Priority{Reachable: &reachable}
	loc := normalize.Location{Path: path}
	if len(f.Trace) > 0 && f.Trace[0].Position.Line > 0 {
		line := f.Trace[0].Position.Line
		loc.StartLine = &line
	}
	finding.AddLocation(loc)
	finding.Fingerprint = normalize.Fingerprint(&finding)
	return finding
}

func (a *Adapter) relative(path string) string {
	return adapter.RelativePath(a.Root, adapter.ContainerRoot, path)
}

func (a *Adapter) Redact(raw []byte) []byte {
	return a.Masker.RedactBytes(raw, nil)
}

func hasLanguage(u discovery.Unit, l discovery.Language) bool {
	for _, x := range u.Languages {
		if x == l {
			return true
		}
	}
	return false
}

func hasManifest(u discovery.Unit, name string) bool {
	for _, m := range u.Manifests {
		if filepath.Base(m) == name {
			return true
		}
	}
	return false
}

func idType(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "CVE"
	case strings.HasPrefix(id, "GHSA-"):
		return "GHSA"
	case strings.HasPrefix(id, "GO-"):
		return "GO"
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "RUSTSEC"
	}
	return "OSV"
}

func summaryOf(osv *OSV) string {
	if osv == nil {
		return ""
	}
	return osv.Summary
}

func severityOf(osv *OSV) string {
	if osv == nil {
		return ""
	}
	return osv.DatabaseSpecific.Severity
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func goEnvironment(goBinary string) map[string]string {
	if goBinary == "" {
		return nil
	}
	env := toolchainEnv()
	for _, key := range []string{"GOMODCACHE", "GOCACHE", "GOPATH"} {
		out, err := exec.Command(goBinary, "env", key).Output() // #nosec G204 -- ruta de PATH
		if err == nil {
			env[key] = strings.TrimSpace(string(out))
		}
	}
	return env
}

func (a *Adapter) env() map[string]string {
	out := make(map[string]string, len(a.GoEnv)+7)
	for k, v := range a.GoEnv {
		out[k] = v
	}
	for k, v := range toolchainEnv() {
		out[k] = v
	}
	return out
}

// toolchainEnv evita descargas de módulos durante el escaneo. GOSUMDB se
// mantiene activo para que el envoltorio de Go pueda verificar un toolchain ya
// cacheado; las conexiones siguen bloqueadas por el proxy inválido del runner.
func toolchainEnv() map[string]string {
	return map[string]string{
		"GOPROXY": "off", "GOSUMDB": "sum.golang.org",
		"GOFLAGS": "-mod=readonly",
	}
}

// RecipeCandidates propone los comandos estándar de Go.
func (a *Adapter) RecipeCandidates(u discovery.Unit) []adapter.RecipeCandidate {
	return []adapter.RecipeCandidate{
		{Unit: u.ID, Kind: "test", Command: "go test ./...", Workdir: u.Path, Origin: "adapter"},
		{Unit: u.ID, Kind: "build", Command: "go build ./...", Workdir: u.Path, Origin: "adapter"},
	}
}
