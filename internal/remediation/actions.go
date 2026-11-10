package remediation

import (
	"sort"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// Actions construye la lista ordenada de próximos pasos. Es determinista:
// primero las carencias que bloquean la validación, después los grupos por
// prioridad, y al final las herramientas ausentes.
func Actions(doc *report.Document, groups []report.RemediationGroup) []report.NextAction {
	if doc == nil {
		return []report.NextAction{}
	}
	out := make([]report.NextAction, 0, len(groups)+4)

	unresolved := append([]report.Unresolved(nil), doc.Validation.Unresolved...)
	sort.SliceStable(unresolved, func(i, j int) bool { return unresolved[i].Unit < unresolved[j].Unit })
	for _, u := range unresolved {
		path := unitPath(doc, u.Unit)
		out = append(out, report.NextAction{
			Action: "confirm_recipes", Unit: u.Unit,
			Command: "cgc-scan scan " + shellArg(path) + " --confirm-recipes",
			Reason:  "validación bloqueada: faltan recetas " + strings.Join(u.Missing, ", "),
		})
	}

	for _, g := range groups {
		switch g.Kind {
		case "secret_rotation":
			fp := ""
			if len(g.Fixes) > 0 {
				fp = g.Fixes[0]
			}
			out = append(out, report.NextAction{
				Action: "revoke_secret", Unit: g.Unit, Group: g.ID, Fingerprint: fp,
				UserRequired: true, Fixes: len(g.Fixes),
				Command: g.Verification.Verify,
				Reason:  "revocar y rotar la credencial; el reescaneo solo confirma que ya no aparece",
			})
		case "dependency_upgrade":
			reason := "actualizar la dependencia"
			if g.Package != nil {
				reason = "actualizar " + g.Package.Name + " a " + g.Package.To
				if g.BreakingRisk != "" && g.BreakingRisk != "unknown" {
					reason += " (riesgo " + g.BreakingRisk + ")"
				}
			}
			if g.Commands.Apply == "" {
				reason = "sin comando sugerido para el ecosistema; revisar el aviso"
			}
			out = append(out, report.NextAction{
				Action: "apply_group", Unit: g.Unit, Group: g.ID,
				Command: g.Commands.Apply, Fixes: len(g.Fixes), Reason: reason,
			})
		case "code_fix":
			out = append(out, report.NextAction{
				Action: "fix_code", Unit: g.Unit, Group: g.ID, Fixes: len(g.Fixes),
				Command: g.Verification.Verify,
				Reason:  "corregir " + itoa(g.Locations) + " ubicación(es) de " + g.Rule + " en " + g.File,
			})
		case "config_fix":
			out = append(out, report.NextAction{
				Action: "fix_config", Unit: g.Unit, Group: g.ID, Fixes: len(g.Fixes),
				Command: g.Verification.Verify,
				Reason:  "corregir la configuración " + g.Rule + " en " + g.File,
			})
		}
	}

	toolActions := map[string]report.NextAction{}
	for _, e := range doc.Errors {
		if e.Code != "requirement_missing" {
			continue
		}
		engine, unit := splitScope(e.Scope)
		action := report.NextAction{
			Action: "install_toolchain", Unit: unit, Tool: toolFor(engine),
			Reason: e.Message,
		}
		if strings.Contains(strings.ToLower(e.Message), "base") ||
			strings.Contains(strings.ToLower(e.Message), "vulndb") ||
			strings.Contains(strings.ToLower(e.Message), "rustsec") {
			action.Action = "update_db"
			action.Tool = engine
			action.Command = "cgc-scan update-db"
		}
		key := engine + "|" + unit
		if prev, ok := toolActions[key]; !ok || action.Reason < prev.Reason {
			toolActions[key] = action
		}
	}
	keys := make([]string, 0, len(toolActions))
	for k := range toolActions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out = append(out, toolActions[k])
	}
	return out
}

func unitPath(doc *report.Document, id string) string {
	for _, u := range doc.Target.Units {
		if u.ID == id {
			if u.Path == "" {
				return "."
			}
			return u.Path
		}
	}
	return "."
}

func splitScope(scope string) (engine, unit string) {
	if i := strings.Index(scope, ":"); i >= 0 {
		return scope[:i], scope[i+1:]
	}
	return scope, ""
}

func toolFor(engine string) string {
	switch engine {
	case "psalm":
		return "composer install"
	case "eslint":
		return "npm install"
	case "bandit":
		return "pip install -r requirements.txt"
	case "govulncheck":
		return "go install"
	default:
		return engine
	}
}

func shellArg(s string) string {
	if s == "" {
		return "."
	}
	if !strings.ContainsAny(s, " \t\n'\"$&|;<>()*?[]{}!#~`\\") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
