// Package orchestrator ejecuta los motores con concurrencia limitada,
// cancelación y resultados parciales (RF-07, RF-08, design §12).
package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// Engine agrupa un adaptador con el runner y los datos que van al reporte.
type Engine struct {
	ID         string
	Version    string
	Mode       string
	Adapter    adapter.Adapter
	Runner     runner.Runner
	Isolation  runner.IsolationLevel
	BinaryPath string
	Image      string
}

// UnitState es el estado de un motor en una unidad.
type UnitState struct {
	Unit     string `json:"unit"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Findings int    `json:"findings,omitempty"`
}

// DBRef describe la base que usó un motor.
type DBRef struct {
	Source    string
	Status    string
	UpdatedAt time.Time
	Detail    string
}

// RulesRef describe el conjunto de reglas de un motor.
type RulesRef struct {
	Source  string
	Version string
	Count   int
}

// EngineResult es el resultado agregado de un motor.
type EngineResult struct {
	ID          string
	Version     string
	Mode        string
	Status      string
	Isolation   runner.IsolationLevel
	Duration    time.Duration
	Findings    int
	Units       []UnitState
	Diagnostics []string
	DB          *DBRef
	Rules       *RulesRef
	Path        string
	Image       string
}

// RunError es un error estructurado del reporte.
type RunError struct {
	Code      string
	Scope     string
	Message   string
	Retryable bool
}

// RawOutput es la salida original de un motor, ya enmascarada, para
// persistirla (design §5.2, H4-13).
type RawOutput struct {
	Engine string
	Unit   string
	Data   []byte
}

// Outcome es el resultado de la orquestación.
type Outcome struct {
	Plan       plan.Plan
	Findings   []normalize.Finding
	Engines    []EngineResult
	Errors     []RunError
	RawOutputs []RawOutput
	Complete   bool
	Canceled   bool
}

// Execute corre todos los motores aplicables. Un fallo de un motor no impide
// que los demás entreguen resultados, pero marca la ejecución como incompleta.
func Execute(ctx context.Context, p plan.Plan, engines []Engine, concurrency int) Outcome {
	if concurrency < 1 {
		concurrency = 4
	}
	out := Outcome{Plan: p, Complete: true}
	states := make(map[string][]UnitState, len(engines))
	findingsByEngine := make(map[string]int, len(engines))
	durations := make(map[string]time.Duration, len(engines))
	var (
		mu      sync.Mutex
		invalid bool
	)

	limit := concurrency
	if limit > 8 {
		limit = 8
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)

	for _, u := range p.Units {
		for _, e := range engines {
			u, e := u, e
			if !e.Adapter.Applies(u.Unit) {
				mu.Lock()
				p.SetEngineStatus(u.Unit.ID, e.ID, plan.StatusSkipped, "not_applicable")
				states[e.ID] = append(states[e.ID], UnitState{Unit: u.Unit.ID, Status: plan.StatusSkipped, Reason: "not_applicable"})
				mu.Unlock()
				continue
			}
			g.Go(func() error {
				if err := gctx.Err(); err != nil {
					return err
				}
				status, findings, duration, diags, errs, used, raw := runOne(gctx, p, u, e)
				mu.Lock()
				defer mu.Unlock()
				p.SetEngineStatus(u.Unit.ID, e.ID, status, reasonOf(errs))
				states[e.ID] = append(states[e.ID], UnitState{Unit: u.Unit.ID, Status: status, Reason: reasonOf(errs), Findings: findings})
				if status != plan.StatusCompleted {
					invalid = true
				}
				findingsByEngine[e.ID] += findings
				out.Findings = append(out.Findings, used...)
				out.Errors = append(out.Errors, errs...)
				out.RawOutputs = append(out.RawOutputs, raw...)
				durations[e.ID] += duration
				_ = diags
				return nil
			})
		}
	}

	_ = g.Wait()

	for _, e := range engines {
		units := states[e.ID]
		status := plan.StatusSkipped
		failed, completed := 0, 0
		for _, s := range units {
			switch s.Status {
			case plan.StatusFailed:
				failed++
			case plan.StatusCompleted:
				completed++
			}
		}
		switch {
		case failed > 0:
			status = plan.StatusFailed
		case completed > 0:
			status = plan.StatusCompleted
		}
		out.Engines = append(out.Engines, EngineResult{
			ID:        e.ID,
			Version:   e.Version,
			Mode:      e.Mode,
			Status:    status,
			Isolation: e.Isolation,
			Duration:  durations[e.ID],
			Findings:  findingsByEngine[e.ID],
			Units:     units,
			Path:      e.BinaryPath,
			Image:     e.Image,
		})
	}

	out.Plan = p
	out.Complete = !invalid && ctx.Err() == nil
	out.Canceled = ctx.Err() != nil
	normalize.SortFindings(out.Findings)
	sort.Slice(out.Errors, func(i, j int) bool {
		if out.Errors[i].Code == out.Errors[j].Code {
			return out.Errors[i].Scope < out.Errors[j].Scope
		}
		return out.Errors[i].Code < out.Errors[j].Code
	})
	return out
}

func runOne(ctx context.Context, p plan.Plan, u plan.UnitPlan, e Engine) (string, int, time.Duration, []string, []RunError, []normalize.Finding, []RawOutput) {
	start := time.Now()
	for _, req := range e.Adapter.Requirements(ctx, u.Unit) {
		if req.Missing {
			return plan.StatusSkipped, 0, time.Since(start),
				[]string{"requisito ausente: " + req.Name},
				[]RunError{{
					Code:    "requirement_missing",
					Scope:   e.ID + ":" + u.Unit.ID,
					Message: fmt.Sprintf("falta %s (%s); la unidad no se analizó", req.Name, req.Detail),
				}}, nil, nil
		}
	}

	invs, err := e.Adapter.Invocations(u.Unit, p)
	if err != nil {
		return plan.StatusFailed, 0, time.Since(start), nil, []RunError{{
			Code: "invocation_failed", Scope: e.ID + ":" + u.Unit.ID, Message: err.Error(),
		}}, nil, nil
	}

	var (
		findings []normalize.Finding
		errs     []RunError
		diags    []string
		rawOut   []RawOutput
	)
	for _, inv := range invs {
		res, runErr := e.Runner.Run(ctx, inv)
		if runErr != nil {
			errs = append(errs, RunError{
				Code: "engine_failed", Scope: e.ID + ":" + u.Unit.ID,
				Message: runErr.Error(), Retryable: true,
			})
			continue
		}
		accepted := res.ExitCode == 0
		if !accepted {
			if policy, ok := e.Adapter.(adapter.ExitPolicy); ok && policy.AcceptExit(res.ExitCode) {
				accepted = true
			}
		}
		if !accepted {
			errs = append(errs, RunError{
				Code: "engine_exit", Scope: e.ID + ":" + u.Unit.ID,
				Message: fmt.Sprintf("el motor terminó con código %d", res.ExitCode),
			})
			continue
		}
		rawOut = append(rawOut, RawOutput{
			Engine: e.ID, Unit: u.Unit.ID, Data: e.Adapter.Redact(res.Stdout),
		})
		parsed, parseErr := e.Adapter.Parse(res.Stdout)
		for _, d := range parsed.Diagnostics {
			diags = append(diags, d.Message)
		}
		if parseErr != nil {
			errs = append(errs, RunError{
				Code: "parse_failed", Scope: e.ID + ":" + u.Unit.ID, Message: parseErr.Error(),
			})
			continue
		}
		findings = append(findings, parsed.Findings...)
	}
	status := plan.StatusCompleted
	if len(errs) > 0 {
		status = plan.StatusFailed
	}
	return status, len(findings), time.Since(start), diags, errs, findings, rawOut
}

func reasonOf(errs []RunError) string {
	if len(errs) == 0 {
		return ""
	}
	return errs[0].Code
}
