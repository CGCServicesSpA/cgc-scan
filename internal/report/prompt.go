package report

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/template"

	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
)

// PromptTemplateVersion identifica la plantilla del formato prompt.
const PromptTemplateVersion = "1.0.0"

// DefaultPromptBatchChars es el umbral de división por lote (D-04).
const DefaultPromptBatchChars = 120000

//go:embed prompt/v1.tmpl
var promptTemplateText string

// PromptOptions ajusta la generación.
type PromptOptions struct {
	// ReportPath es la ruta del JSON canónico si --report-out se usó.
	ReportPath string
	// BatchChars fuerza el umbral; 0 usa el valor por defecto.
	BatchChars int
}

type promptFinding struct {
	Index       int
	Fingerprint string
	Kind        string
	Severity    string
	Title       string
	Locations   []string
	Package     string
	IDs         string
	Sources     string
	Evidence    string
	Remediation string
}

type promptRecipe struct {
	Unit, Kind, Command, Workdir, Origin string
}

type promptUnresolved struct {
	Unit    string
	Missing []string
}

type promptBatch struct {
	TemplateVersion string
	SchemaVersion   string
	RunID           string
	TargetRoot      string
	CoverageState   string
	CoverageNotes   []string
	PolicyState     string
	Recipes         []promptRecipe
	Unresolved      []promptUnresolved
	Findings        []promptFinding
	NonceStart      string
	NonceEnd        string
	BatchNote       string
}

// EmitPrompt genera el prompt de remediación. Nunca llama a un modelo ni
// ejecuta comandos; solo convierte el reporte con una plantilla versionada.
func EmitPrompt(w io.Writer, doc *Document, opts PromptOptions) error {
	if opts.BatchChars == 0 {
		opts.BatchChars = DefaultPromptBatchChars
	}
	batches := planPromptBatches(doc, opts)
	tmpl, err := template.New("prompt").Parse(promptTemplateText)
	if err != nil {
		return fmt.Errorf("plantilla de prompt inválida: %w", err)
	}
	for i, b := range batches {
		if i > 0 {
			if _, err := io.WriteString(w, "\n\n"); err != nil {
				return err
			}
		}
		if err := tmpl.Execute(w, b); err != nil {
			return fmt.Errorf("renderizar prompt: %w", err)
		}
	}
	return nil
}

func planPromptBatches(doc *Document, opts PromptOptions) []promptBatch {
	base := promptBatch{
		TemplateVersion: PromptTemplateVersion,
		SchemaVersion:   doc.SchemaVersion,
		RunID:           doc.Run.ID,
		TargetRoot:      masking.Sanitize(doc.Target.Root),
		CoverageState:   "COMPLETA",
		PolicyState:     policyState(doc),
		Recipes:         []promptRecipe{},
		Unresolved:      []promptUnresolved{},
	}
	if doc.Coverage.Partial {
		base.CoverageState = "PARCIAL"
	}
	if len(doc.Errors) > 0 {
		base.CoverageState = "INCOMPLETA"
	}
	if doc.Coverage.Partial {
		base.CoverageNotes = append(base.CoverageNotes,
			"El alcance se restringió por selección de rutas o exclusiones elegidas; lo no evaluado no se declara resuelto.")
	}
	for _, n := range doc.Coverage.NotAnalyzed {
		base.CoverageNotes = append(base.CoverageNotes,
			"no analizado: "+masking.Sanitize(n.Path)+" ("+masking.Sanitize(n.Reason)+")")
	}
	for _, e := range doc.Errors {
		base.CoverageNotes = append(base.CoverageNotes,
			"error: "+masking.Sanitize(e.Code)+" en "+masking.Sanitize(e.Scope))
	}
	if len(doc.Errors) > 0 {
		base.CoverageNotes = append(base.CoverageNotes, "La ejecución no se completó; ningún hallazgo ausente puede considerarse resuelto.")
	}
	for _, r := range doc.Validation.Recipes {
		base.Recipes = append(base.Recipes, promptRecipe{
			Unit: masking.Sanitize(r.Unit), Kind: r.Kind,
			Command: masking.Sanitize(r.Command), Workdir: masking.Sanitize(r.Workdir),
			Origin: r.Origin,
		})
	}
	for _, u := range doc.Validation.Unresolved {
		base.Unresolved = append(base.Unresolved, promptUnresolved{
			Unit: masking.Sanitize(u.Unit), Missing: u.Missing,
		})
	}

	all := make([]promptFinding, 0, len(doc.Findings))
	for i, f := range doc.Findings {
		all = append(all, promptFindingOf(i+1, f))
	}

	// Si todo cabe, un solo documento.
	base.Findings = all
	base.NonceStart, base.NonceEnd = newNoncePair(base)
	if promptSize(base) <= opts.BatchChars || len(all) <= 1 {
		return []promptBatch{base}
	}

	// División por unidad de parche (primera ubicación) conservando el índice.
	groups := map[string][]promptFinding{}
	var order []string
	for _, f := range all {
		key := "sin-ubicación"
		if len(f.Locations) > 0 {
			key = strings.SplitN(f.Locations[0], ":", 2)[0]
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], f)
	}
	sort.Strings(order)
	var batches []promptBatch
	for _, key := range order {
		b := base
		b.Findings = groups[key]
		b.BatchNote = fmt.Sprintf("LOTE de la unidad %s", masking.Sanitize(key))
		if b.Unresolved == nil {
			b.Unresolved = []promptUnresolved{}
		}
		batches = append(batches, b)
	}
	for i := range batches {
		batches[i].BatchNote = fmt.Sprintf("LOTE %d/%d — %s", i+1, len(batches), batches[i].BatchNote)
		batches[i].CoverageNotes = append(append([]string{}, base.CoverageNotes...), batchReference(opts))
		batches[i].NonceStart, batches[i].NonceEnd = newNoncePair(batches[i])
	}
	return batches
}

func batchReference(opts PromptOptions) string {
	if opts.ReportPath != "" {
		return "El reporte completo y canónico está en " + masking.Sanitize(opts.ReportPath) + "."
	}
	return "Este prompt está dividido en lotes; el reporte completo no se persistió. Ejecuta con --report-out para conservarlo y consultar los hallazgos omitidos de este lote."
}

func promptFindingOf(index int, f normalize.Finding) promptFinding {
	pf := promptFinding{
		Index:       index,
		Fingerprint: f.Fingerprint,
		Kind:        string(f.Kind),
		Severity:    string(f.Severity.Normalized),
		Title:       masking.Sanitize(f.Title),
		Sources:     hygienicSources(f),
		IDs:         hygienicIDs(f),
	}
	for _, l := range f.Locations {
		line := masking.Sanitize(l.Path)
		if l.StartLine != nil {
			line += fmt.Sprintf(":%d", *l.StartLine)
		}
		pf.Locations = append(pf.Locations, line)
	}
	if f.Package != nil {
		pf.Package = masking.Sanitize(f.Package.Name + " " + f.Package.Version)
		if f.Package.FixedVersion != nil {
			pf.Package += " -> " + masking.Sanitize(*f.Package.FixedVersion)
		}
	}
	if f.Evidence.Snippet != "" {
		pf.Evidence = masking.Sanitize(f.Evidence.Snippet)
	}
	for _, r := range f.Remediation {
		if pf.Remediation != "" {
			pf.Remediation += "; "
		}
		pf.Remediation += masking.Sanitize(r.Description)
	}
	return pf
}

func hygienicSources(f normalize.Finding) string {
	var parts []string
	for _, s := range f.Sources {
		parts = append(parts, masking.Sanitize(s.Engine))
	}
	return strings.Join(parts, ", ")
}

func hygienicIDs(f normalize.Finding) string {
	var parts []string
	for _, id := range f.IDs {
		parts = append(parts, masking.Sanitize(id.Type+":"+id.Value))
	}
	return strings.Join(parts, ", ")
}

func policyState(doc *Document) string {
	if doc.Policy.Violated {
		return fmt.Sprintf("fail-on %s INCUMPLIDA (%d suprimidos)", doc.Policy.FailOn, doc.Policy.SuppressedCount)
	}
	return fmt.Sprintf("fail-on %s cumplida (%d suprimidos)", doc.Policy.FailOn, doc.Policy.SuppressedCount)
}

func promptSize(b promptBatch) int {
	tmpl, err := template.New("size").Parse(promptTemplateText)
	if err != nil {
		return 0
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, b); err != nil {
		return 0
	}
	return buf.Len()
}

func newNoncePair(b promptBatch) (string, string) {
	for i := 0; i < 100; i++ {
		nonce := randomNonce()
		start := "<<<CGC_DATOS_NO_CONFIABLES_" + nonce + ">>>"
		end := "<<<FIN_CGC_DATOS_NO_CONFIABLES_" + nonce + ">>>"
		if !promptContains(b, nonce) {
			return start, end
		}
	}
	// En la práctica es imposible; un nonce fijo de respaldo mantiene el
	// delimitador aunque degrade la aleatoriedad (se prefiere no fallar).
	return "<<<CGC_DATOS_NO_CONFIABLES_FALLBACK>>>", "<<<FIN_CGC_DATOS_NO_CONFIABLES_FALLBACK>>>"
}

func promptContains(b promptBatch, s string) bool {
	for _, f := range b.Findings {
		if strings.Contains(f.Title, s) || strings.Contains(f.Evidence, s) || strings.Contains(f.Remediation, s) {
			return true
		}
	}
	return strings.Contains(b.TargetRoot, s)
}

func randomNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
