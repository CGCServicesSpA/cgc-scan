package audit

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/CGCServicesSpA/cgc-scan/internal/masking"
)

// TaskPromptTemplateVersion identifica la plantilla del formato prompt de
// tareas. Cambia solo con un cambio de forma del render.
const TaskPromptTemplateVersion = "1.0.0"

//go:embed prompt/v1.tmpl
var taskPromptTemplateText string

// kindRules son las reglas específicas de cada tipo de tarea.
var kindRules = map[string]string{
	"hunt": "- Cubre cada unidad asignada revisando sus rutas y comprobando los\n" +
		"  checks de la clase representativa. Si una unidad merece unidad propia,\n" +
		"  declárala en uncovered; no investigues unidades de otros agentes.\n",
	"verify": "- Verifica el candidato propuesto de forma independiente: no confíes en\n" +
		"  la propuesta; comprueba la traza y la evidencia en la fuente declarada.\n" +
		"  El veredicto es confirmed, needs_validation o rejected, con su contrato.\n",
	"escalation_check": "- Revisa el registro escalado por una promoción de veredicto: confírmalo\n" +
		"  con verified o sustitúyelo con replace y un registro propio válido.\n",
	"final_review": "- Revisa el registro final: apruébalo con verified o reemplázalo con\n" +
		"  replace y un registro propio válido. Un reemplazo material (veredicto,\n" +
		"  causa raíz, traza, ejecución, impacto o severidad) exigirá un\n" +
		"  verificador independiente de ti.\n",
	"critique": "- Critica la cobertura declarada del proyecto: identifica superficies\n" +
		"  omitidas y unidades con evidencia débil. Si no queda nada por mapear,\n" +
		"  responde stop con su razón.\n",
}

// responseContracts es el contrato de respuesta exigido por tipo de tarea.
var responseContracts = map[string]string{
	"hunt": `Entrega un JSON audit-submission-1.0.0 con:
{"schema_version":"audit-submission-1.0.0","agent_id":"<id>",
 "units":[{"coverage_id","disposition":"covered|candidate|blocked",
   "reviewed_paths":[...],"checks":[{"agent_id","reviewed_paths","invariant",
   "method":"source|local","result","artifact"}],
   "candidate_fingerprints":[...],"unresolved":[...],"hardening":[...]}],
 "uncovered":[{"surface","domain","boundary","subsystem","attack_class",
   "starting_paths":[...],"reason"}]}`,
	"verify": `Entrega un JSON audit-submission-1.0.0 con:
{"schema_version":"audit-submission-1.0.0","agent_id":"<id>",
 "verification":{"fingerprint":"<fp>","decision":"confirmed|needs_validation|rejected",
 "record":{"verdict","fingerprint","title","description","trace":[...],
 "evidence":[...], ...campos del veredicto...}}}`,
	"escalation_check": `Entrega un JSON audit-submission-1.0.0 con:
{"schema_version":"audit-submission-1.0.0","agent_id":"<id>",
 "verification":{"fingerprint":"<fp>","decision":"verified|replace",
 "record":{...solo con replace...}}}`,
	"final_review": `Entrega un JSON audit-submission-1.0.0 con:
{"schema_version":"audit-submission-1.0.0","agent_id":"<id>",
 "verification":{"fingerprint":"<fp>","decision":"verified|replace",
 "record":{...solo con replace...}}}`,
	"critique": `Entrega un JSON audit-submission-1.0.0 con:
{"schema_version":"audit-submission-1.0.0","agent_id":"<id>",
 "critique":{"missing_units":[{"surface","domain","boundary","subsystem",
   "attack_class","starting_paths":[...],"reason"}],
   "reassign_ids":["<coverage_id>"],"resolved_prior_leads":["<fp>"],
   "stop":false,"reason":"<solo con stop>"}}`,
}

type taskPromptData struct {
	TemplateVersion  string
	Kind             string
	RunID            string
	TargetRoot       string
	KindRules        string
	ResponseContract string
	TaskData         string
	NonceStart       string
	NonceEnd         string
}

// EmitTaskPrompt renderiza una asignación como prompt. El contenido del
// proyecto y del agente es un dato no confiable: se sanea y se delimita con
// un nonce. El nonce "" genera uno aleatorio; las pruebas fijan uno propio
// que no puede aparecer en el contenido saneado.
func EmitTaskPrompt(w io.Writer, t *Task, root, nonce string) error {
	if t == nil {
		return fmt.Errorf("auditoría: no hay tarea que renderizar")
	}
	if kindRules[t.Kind] == "" || responseContracts[t.Kind] == "" {
		return fmt.Errorf("auditoría: tipo de tarea desconocido: %q", t.Kind)
	}
	if nonce == "" {
		nonce = randomTaskNonce()
	}
	data := taskPromptData{
		TemplateVersion:  TaskPromptTemplateVersion,
		Kind:             t.Kind,
		RunID:            t.RunID,
		TargetRoot:       masking.Sanitize(root),
		KindRules:        kindRules[t.Kind],
		ResponseContract: responseContracts[t.Kind],
		TaskData:         taskDataOf(t),
	}
	if data.TaskData == "" {
		return fmt.Errorf("auditoría: la tarea %s no trae los datos que su tipo exige", t.Kind)
	}
	if strings.Contains(data.TaskData, nonce) {
		return fmt.Errorf("auditoría: el nonce aparece en el contenido de la tarea")
	}
	data.NonceStart = "<<<CGC_DATOS_NO_CONFIABLES_" + nonce + ">>>"
	data.NonceEnd = "<<<FIN_CGC_DATOS_NO_CONFIABLES_" + nonce + ">>>"

	tmpl, err := template.New("task-prompt").Parse(taskPromptTemplateText)
	if err != nil {
		return fmt.Errorf("plantilla de tarea inválida: %w", err)
	}
	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("renderizar tarea como prompt: %w", err)
	}
	return nil
}

// taskDataOf renderiza el bloque de datos de la tarea, saneando todo el
// contenido interpolado.
func taskDataOf(t *Task) string {
	var b strings.Builder
	switch t.Kind {
	case "hunt":
		for _, au := range t.Units {
			fmt.Fprintf(&b, "[UNIDAD %s] clase %s · %s/%s\n",
				masking.Sanitize(au.Unit.CoverageID), masking.Sanitize(au.Unit.AttackClass),
				masking.Sanitize(au.Unit.Domain), masking.Sanitize(au.Unit.Boundary))
			fmt.Fprintf(&b, "  rutas de partida:\n")
			for _, p := range au.Unit.StartingPaths {
				fmt.Fprintf(&b, "    %s\n", masking.Sanitize(p))
			}
			if au.Class.Invariant != "" {
				fmt.Fprintf(&b, "  invariante: %s\n", masking.Sanitize(au.Class.Invariant))
			}
			for _, c := range au.Class.Checks {
				fmt.Fprintf(&b, "  check: %s\n", masking.Sanitize(c))
			}
		}
	case "verify", "escalation_check", "final_review":
		if t.Candidate == nil {
			return ""
		}
		c := t.Candidate
		fmt.Fprintf(&b, "[CANDIDATO %s] unidad %s\n", masking.Sanitize(c.Fingerprint), masking.Sanitize(c.Unit))
		fmt.Fprintf(&b, "  propuesta: verdict=%s\n", masking.Sanitize(c.Proposed.Verdict))
		fmt.Fprintf(&b, "  título: %s\n", masking.Sanitize(c.Proposed.Title))
		fmt.Fprintf(&b, "  descripción: %s\n", masking.Sanitize(clipRecordText(c.Proposed.Description, 800)))
		for i, step := range c.Proposed.Trace {
			fmt.Fprintf(&b, "  traza[%d]: %s %s:%d %s\n", i, masking.Sanitize(step.Kind),
				masking.Sanitize(step.File), step.Line, masking.Sanitize(step.Description))
		}
		for i, ev := range c.Proposed.Evidence {
			fmt.Fprintf(&b, "  evidencia[%d]: %s:%d %s\n", i, masking.Sanitize(ev.File), ev.Line, masking.Sanitize(ev.Description))
		}
		if c.Escalated != nil {
			fmt.Fprintf(&b, "  registro escalado por la promoción: verdict=%s\n", masking.Sanitize(c.Escalated.Verdict))
		}
		if c.Final != nil {
			fmt.Fprintf(&b, "  registro final a revisar: verdict=%s\n", masking.Sanitize(c.Final.Verdict))
			fmt.Fprintf(&b, "  título: %s\n", masking.Sanitize(c.Final.Title))
			for i, step := range c.Final.Trace {
				fmt.Fprintf(&b, "  traza[%d]: %s %s:%d %s\n", i, masking.Sanitize(step.Kind),
					masking.Sanitize(step.File), step.Line, masking.Sanitize(step.Description))
			}
			for i, ev := range c.Final.Evidence {
				fmt.Fprintf(&b, "  evidencia[%d]: %s:%d %s\n", i, masking.Sanitize(ev.File), ev.Line, masking.Sanitize(ev.Description))
			}
		}
	case "critique":
		fmt.Fprintf(&b, "[CRÍTICA DE COBERTURA]\n")
		fmt.Fprintf(&b, "  Evalúa el mapa de cobertura del proyecto en la fuente declarada:\n")
		fmt.Fprintf(&b, "  superficies de ataque sin unidad propia y unidades con evidencia\n")
		fmt.Fprintf(&b, "  débil. Usa la clase de tu respuesta para declararlas.\n")
	}
	return b.String()
}

// clipRecordText recorta un texto interpolado al tamaño pedido.
func clipRecordText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}

func randomTaskNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
