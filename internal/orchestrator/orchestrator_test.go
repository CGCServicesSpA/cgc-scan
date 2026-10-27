package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/adapter"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/normalize"
	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

type stubAdapter struct {
	id string
}

func (s *stubAdapter) ID() string                  { return s.id }
func (s *stubAdapter) Applies(discovery.Unit) bool { return true }
func (s *stubAdapter) Requirements(context.Context, discovery.Unit) []adapter.Requirement {
	return nil
}
func (s *stubAdapter) Invocations(u discovery.Unit, p plan.Plan) ([]runner.Invocation, error) {
	return []runner.Invocation{{Engine: s.id, Binary: "/bin/true", Dir: u.Path}}, nil
}
func (s *stubAdapter) Parse([]byte) (adapter.Parsed, error) {
	f := normalize.Finding{
		Kind:     normalize.KindCode,
		Title:    "hallazgo de prueba",
		Severity: normalize.SeverityInfo{Original: "high", Normalized: normalize.SeverityHigh, Source: s.id},
		Sources:  []normalize.SourceRef{{Engine: s.id}},
		Evidence: normalize.Evidence{Redacted: true},
	}
	f.Fingerprint = normalize.Fingerprint(&f)
	return adapter.Parsed{Findings: []normalize.Finding{f}}, nil
}
func (s *stubAdapter) Redact(b []byte) []byte { return b }

type stubRunner struct {
	failDir string
}

func (s *stubRunner) Kind() string { return "stub" }
func (s *stubRunner) Isolation(context.Context) (runner.IsolationLevel, error) {
	return runner.IsolationConfigured, nil
}
func (s *stubRunner) Run(_ context.Context, inv runner.Invocation) (runner.Result, error) {
	if s.failDir != "" && inv.Dir == s.failDir {
		return runner.Result{ExitCode: -1}, errors.New("el motor explotó")
	}
	return runner.Result{ExitCode: 0, Stdout: []byte(`{}`)}, nil
}

func testPlan() plan.Plan {
	d := discovery.Result{
		Root: "/repo",
		Units: []discovery.Unit{
			{ID: "a", Path: "a", Kind: "module"},
			{ID: "b", Path: "b", Kind: "module"},
		},
	}
	return plan.Build(d, []string{"stub"})
}

func TestExecuteCompletesAllUnits(t *testing.T) {
	p := testPlan()
	out := Execute(context.Background(), p, []Engine{{
		ID: "stub", Version: "1.0.0", Mode: "global",
		Adapter: &stubAdapter{id: "stub"}, Runner: &stubRunner{},
		Isolation: runner.IsolationConfigured,
	}}, 2)
	if !out.Complete {
		t.Fatalf("ejecución incompleta: %+v", out.Errors)
	}
	if len(out.Findings) != 2 {
		t.Fatalf("hallazgos = %d", len(out.Findings))
	}
	if len(out.Engines) != 1 || out.Engines[0].Status != plan.StatusCompleted {
		t.Fatalf("motores = %+v", out.Engines)
	}
	for _, u := range out.Plan.Units {
		if got := out.Plan.UnitStatus(u.Unit.ID); got != plan.StatusCompleted {
			t.Errorf("unidad %s = %s", u.Unit.ID, got)
		}
	}
}

func TestExecuteKeepsPartialResultsOnFailure(t *testing.T) {
	p := testPlan()
	out := Execute(context.Background(), p, []Engine{{
		ID: "stub", Version: "1.0.0", Mode: "global",
		Adapter: &stubAdapter{id: "stub"}, Runner: &stubRunner{failDir: "b"},
		Isolation: runner.IsolationConfigured,
	}}, 2)
	if out.Complete {
		t.Fatal("un fallo de motor debe marcar la ejecución incompleta")
	}
	if len(out.Findings) != 1 {
		t.Fatalf("se perdieron resultados parciales: %d hallazgos", len(out.Findings))
	}
	if len(out.Errors) != 1 || out.Errors[0].Code != "engine_failed" {
		t.Fatalf("errores = %+v", out.Errors)
	}
	if got := out.Plan.UnitStatus("b"); got != plan.StatusFailed {
		t.Fatalf("unidad b = %s", got)
	}
}

func TestExecuteCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := testPlan()
	out := Execute(ctx, p, []Engine{{
		ID: "stub", Version: "1.0.0", Mode: "global",
		Adapter: &stubAdapter{id: "stub"},
		Runner:  &slowRunner{}, Isolation: runner.IsolationConfigured,
	}}, 1)
	if !out.Canceled {
		t.Fatalf("Canceled = false: %+v", out)
	}
}

type slowRunner struct{}

func (s *slowRunner) Kind() string { return "slow" }
func (s *slowRunner) Isolation(context.Context) (runner.IsolationLevel, error) {
	return runner.IsolationConfigured, nil
}
func (s *slowRunner) Run(ctx context.Context, _ runner.Invocation) (runner.Result, error) {
	select {
	case <-ctx.Done():
		return runner.Result{Canceled: true}, ctx.Err()
	case <-time.After(2 * time.Second):
		return runner.Result{}, nil
	}
}

func TestRequirementMissingSkipsEngine(t *testing.T) {
	p := testPlan()
	out := Execute(context.Background(), p, []Engine{{
		ID: "stub", Version: "1.0.0", Mode: "global",
		Adapter: &missingAdapter{}, Runner: &stubRunner{}, Isolation: runner.IsolationConfigured,
	}}, 1)
	if out.Complete {
		t.Fatal("un requisito ausente debe marcar la ejecución incompleta")
	}
	if len(out.Errors) != 2 || out.Errors[0].Code != "requirement_missing" {
		t.Fatalf("errores = %+v", out.Errors)
	}
}

type missingAdapter struct{ stubAdapter }

func (m *missingAdapter) Requirements(context.Context, discovery.Unit) []adapter.Requirement {
	return []adapter.Requirement{{Kind: "toolchain", Name: "go", Detail: "no instalado", Missing: true}}
}
