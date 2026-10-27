// Package policyfile interpreta la política declarativa del proyecto
// (cgc-scan.toml) como dato no confiable: solo puede agregar exclusiones,
// agregar excepciones y endurecer el umbral (PRD §6.8, design §4.4).
package policyfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/pelletier/go-toml/v2"

	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/policy"
)

// FileName es el nombre fijo del archivo de política.
const FileName = "cgc-scan.toml"

// Issue es un problema de la política que se registra en el reporte sin
// detener el escaneo (CA-52).
type Issue struct {
	Code    string
	Message string
}

// Policy es la política efectiva del proyecto.
type Policy struct {
	Present    bool
	FailOn     normalize.Severity
	Exclude    []string
	Exceptions []policy.Exception
	Issues     []Issue
}

var allowedKeys = map[string]bool{
	"fail_on":   true,
	"exclude":   true,
	"exception": true,
}

// Load lee <root>/cgc-scan.toml. Nunca falla por una clave prohibida: la
// ignora y registra el problema.
func Load(root string, now time.Time) (Policy, error) {
	path := filepath.Join(root, FileName)
	data, err := platform.ReadFileBounded(path, 1<<20)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Policy{}, nil
		}
		return Policy{}, fmt.Errorf("leer %s: %w", path, err)
	}
	var raw map[string]any
	if err := toml.Unmarshal(data, &raw); err != nil {
		// Un archivo malformado no puede romper el escaneo: se ignora y se
		// registra, igual que una clave prohibida.
		return Policy{Present: true, Issues: []Issue{{
			Code:    "policy_invalid_toml",
			Message: fmt.Sprintf("la política del proyecto no es TOML válido: %v", err),
		}}}, nil
	}

	p := Policy{Present: true}
	for key := range raw {
		if !allowedKeys[key] {
			p.Issues = append(p.Issues, Issue{
				Code:    "policy_key_ignored",
				Message: fmt.Sprintf("la clave %q no está permitida en la política del proyecto y se ignoró", key),
			})
		}
	}

	if v, ok := raw["fail_on"]; ok {
		s, ok := v.(string)
		if !ok {
			p.Issues = append(p.Issues, Issue{Code: "policy_invalid_fail_on", Message: "fail_on debe ser una cadena"})
		} else {
			sev := normalize.Severity(s)
			if !sev.Valid() || sev == normalize.SeverityUnknown {
				p.Issues = append(p.Issues, Issue{Code: "policy_invalid_fail_on", Message: fmt.Sprintf("fail_on inválido: %q", s)})
			} else {
				p.FailOn = sev
			}
		}
	}

	if v, ok := raw["exclude"]; ok {
		list, ok := asList(v)
		if !ok {
			p.Issues = append(p.Issues, Issue{Code: "policy_invalid_exclude", Message: "exclude debe ser una lista de patrones"})
		} else {
			for _, item := range list {
				pat, ok := item.(string)
				if !ok || pat == "" {
					p.Issues = append(p.Issues, Issue{Code: "policy_invalid_exclude", Message: "exclude contiene un patrón vacío o no textual"})
					continue
				}
				if filepath.IsAbs(pat) || pat == ".." || len(pat) > 3 && pat[:3] == "../" {
					p.Issues = append(p.Issues, Issue{Code: "policy_invalid_exclude", Message: fmt.Sprintf("patrón de exclusión no relativo: %q", pat)})
					continue
				}
				if _, err := doublestar.Match(pat, "x"); err != nil {
					p.Issues = append(p.Issues, Issue{Code: "policy_invalid_exclude", Message: fmt.Sprintf("patrón inválido %q: %v", pat, err)})
					continue
				}
				p.Exclude = append(p.Exclude, pat)
			}
		}
	}

	if v, ok := raw["exception"]; ok {
		list, ok := asList(v)
		if !ok {
			p.Issues = append(p.Issues, Issue{Code: "policy_invalid_exception", Message: "exception debe ser una lista de tablas"})
		} else {
			for i, item := range list {
				ex, issue, ok := parseException(item, now)
				if !ok {
					p.Issues = append(p.Issues, Issue{
						Code:    "policy_invalid_exception",
						Message: fmt.Sprintf("exception[%d]: %s", i, issue),
					})
					continue
				}
				p.Exceptions = append(p.Exceptions, ex)
			}
		}
	}
	return p, nil
}

func parseException(item any, now time.Time) (policy.Exception, string, bool) {
	m, ok := asMap(item)
	if !ok {
		return policy.Exception{}, "no es una tabla", false
	}
	fp, _ := m["fingerprint"].(string)
	reason, _ := m["reason"].(string)
	owner, _ := m["owner"].(string)
	if fp == "" {
		return policy.Exception{}, "falta fingerprint", false
	}
	if reason == "" {
		return policy.Exception{}, "falta reason", false
	}
	if owner == "" {
		return policy.Exception{}, "falta owner", false
	}
	expires, ok := parseDate(m["expires"])
	if !ok {
		return policy.Exception{}, "falta expires o no es una fecha YYYY-MM-DD", false
	}
	// La excepción suprime hasta el inicio del día indicado (UTC).
	effective := now.UTC().Before(expires)
	return policy.Exception{
		Fingerprint: fp,
		Reason:      reason,
		Owner:       owner,
		Expires:     expires.Format("2006-01-02"),
		Effective:   effective,
	}, "", true
}

// asList acepta los distintos tipos de slice que puede producir el decoder.
func asList(v any) ([]any, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice {
		return nil, false
	}
	out := make([]any, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out[i] = rv.Index(i).Interface()
	}
	return out, true
}

func asMap(v any) (map[string]any, bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}
	out := make(map[string]any, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		out[iter.Key().String()] = iter.Value().Interface()
	}
	return out, true
}

func parseDate(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), true
	case toml.LocalDate:
		return time.Date(t.Year, time.Month(t.Month), t.Day, 0, 0, 0, 0, time.UTC), true
	case toml.LocalDateTime:
		return time.Date(t.Year, time.Month(t.Month), t.Day, 0, 0, 0, 0, time.UTC), true
	case string:
		d, err := time.Parse("2006-01-02", t)
		if err != nil {
			return time.Time{}, false
		}
		return d.UTC(), true
	}
	return time.Time{}, false
}

// EffectiveFailOn resuelve el umbral con la precedencia
// flag > política del proyecto > valor por defecto. La política solo puede
// endurecer: un valor más débil se ignora y se registra.
func EffectiveFailOn(flagSet bool, flagValue string, project Policy, defaultLevel normalize.Severity) (normalize.Severity, []Issue) {
	if flagSet && flagValue != "" {
		sev := normalize.Severity(flagValue)
		if sev.Valid() {
			return sev, nil
		}
	}
	if project.FailOn == "" {
		return defaultLevel, nil
	}
	if project.FailOn.Rank() < defaultLevel.Rank() {
		return defaultLevel, []Issue{{
			Code:    "policy_weakened_fail_on",
			Message: fmt.Sprintf("la política intentó bajar el umbral a %s; se mantiene %s", project.FailOn, defaultLevel),
		}}
	}
	return project.FailOn, nil
}

// MergeIssues agrega los problemas de la política.
func (p Policy) MergeIssues(extra ...Issue) Policy {
	p.Issues = append(p.Issues, extra...)
	return p
}
