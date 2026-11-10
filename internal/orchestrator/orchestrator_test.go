package orchestrator

import (
	"context"
	"errors"
	"sync"
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

type memoryCache struct {
	mu    sync.Mutex
	items map[string]CachedUnit
	saved int
}

func (m *memoryCache) key(req CacheRequest) string { return req.EngineID + "|" + req.UnitID }
func (m *memoryCache) Lookup(req CacheRequest) (CachedUnit, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.items == nil {
		return CachedUnit{}, false
	}
	v, ok := m.items[m.key(req)]
	return v, ok
}
func (m *memoryCache) Save(req CacheRequest, res CachedUnit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.items == nil {
		m.items = map[string]CachedUnit{}
	}
	m.items[m.key(req)] = res
	m.saved++
	return nil
}

type countingRunner struct {
	stubRunner
	mu    sync.Mutex
	calls int
}

func (c *countingRunner) Run(ctx context.Context, inv runner.Invocation) (runner.Result, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.stubRunner.Run(ctx, inv)
}

func (c *countingRunner) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestExecuteUsesUnitCache(t *testing.T) {
	cache := &memoryCache{}
	runnerCalls := &countingRunner{}
	engine := Engine{
		ID: "stub", Version: "1.0.0", Mode: "global",
		Adapter: &stubAdapter{id: "stub"}, Runner: runnerCalls,
		Isolation: runner.IsolationConfigured, CacheMode: "source",
	}
	first := ExecuteWithOptions(context.Background(), testPlan(), []Engine{engine}, 2, Options{Cache: cache})
	if cache.saved != 2 || runnerCalls.total() != 2 {
		t.Fatalf("primera ejecución: saved=%d calls=%d", cache.saved, runnerCalls.total())
	}
	for _, e := range first.Engines {
		for _, u := range e.Units {
			if u.Cache != "miss" {
				t.Errorf("estado de caché = %q, want miss", u.Cache)
			}
		}
	}
	second := ExecuteWithOptions(context.Background(), testPlan(), []Engine{engine}, 2, Options{Cache: cache})
	if runnerCalls.total() != 2 {
		t.Fatalf("la caché no evitó ejecuciones: %d", runnerCalls.total())
	}
	if len(second.Findings) != 2 {
		t.Fatalf("hallazgos cacheados = %d", len(second.Findings))
	}
	for _, e := range second.Engines {
		if e.Cache != "hit" {
			t.Errorf("caché del motor = %q", e.Cache)
		}
	}
	third := ExecuteWithOptions(context.Background(), testPlan(), []Engine{engine}, 2, Options{Cache: cache, NoCache: true})
	if runnerCalls.total() != 4 {
		t.Fatalf("--no-cache no ejecutó: %d", runnerCalls.total())
	}
	for _, e := range third.Engines {
		if e.Cache != "disabled" {
			t.Errorf("caché con --no-cache = %q", e.Cache)
		}
	}
}
