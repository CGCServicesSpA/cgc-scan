package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
)

func savedRun(t *testing.T, units ...string) (*Store, *Ledger, *Candidates) {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	l := plannerLedger(units...)
	c := &Candidates{SchemaVersion: CandidatesSchemaVersion, RunID: l.Run.ID, Items: []Candidate{}}
	if err := store.SaveLedger(l); err != nil {
		t.Fatalf("save ledger: %v", err)
	}
	if err := store.SaveCandidates(l, c); err != nil {
		t.Fatalf("save candidates: %v", err)
	}
	return store, l, c
}

// nextCycle reproduce el ciclo completo de `audit next` bajo el bloqueo de la
// corrida: cargar, repartir y persistir.
func nextCycle(store *Store, agent string) (*Task, error) {
	var task *Task
	err := store.WithRunLock(context.Background(), 5*time.Second, func() error {
		ledger, err := store.LoadLedger()
		if err != nil {
			return err
		}
		candidates, err := store.LoadCandidates(ledger)
		if err != nil {
			return err
		}
		task, err = Next(ledger, candidates, NextOptions{AgentID: agent, MaxUnits: 1})
		if err != nil {
			return err
		}
		if err := store.SaveLedger(ledger); err != nil {
			return err
		}
		return store.SaveCandidates(ledger, candidates)
	})
	if err != nil {
		return nil, err
	}
	return task, nil
}

func TestStoreLockSerializesAssignments(t *testing.T) {
	store, _, _ := savedRun(t, "sql-injection", "command-injection", "weak-crypto", "path-traversal")
	agents := []string{"hunter-a", "hunter-b", "hunter-c", "hunter-d", "hunter-e", "hunter-f"}

	tasks := make([]*Task, len(agents))
	errs := make([]error, len(agents))
	var wg sync.WaitGroup
	for i, agent := range agents {
		wg.Add(1)
		go func(i int, agent string) {
			defer wg.Done()
			tasks[i], errs[i] = nextCycle(store, agent)
		}(i, agent)
	}
	wg.Wait()

	assigned := map[string]string{}
	for i, agent := range agents {
		switch {
		case errors.Is(errs[i], ErrNoTask):
		case errs[i] != nil:
			t.Fatalf("%s: next: %v", agent, errs[i])
		default:
			if len(tasks[i].Units) != 1 {
				t.Fatalf("%s: tarea con %d unidades", agent, len(tasks[i].Units))
			}
			id := tasks[i].Units[0].Unit.CoverageID
			if other, dup := assigned[id]; dup {
				t.Fatalf("la unidad %s se asignó dos veces: %s y %s", id, other, agent)
			}
			assigned[id] = agent
		}
	}
	if len(assigned) != 4 {
		t.Fatalf("asignaciones = %d, want 4: %v", len(assigned), assigned)
	}

	ledger, err := store.LoadLedger()
	if err != nil {
		t.Fatalf("releer ledger: %v", err)
	}
	if ledger.Budget.Used != 4 {
		t.Fatalf("presupuesto usado = %d, want 4", ledger.Budget.Used)
	}
	for _, u := range ledger.Units {
		if u.State != StateInProgress || u.Wave != 1 {
			t.Fatalf("unidad mal asignada: %+v", u)
		}
		if owner := assigned[u.CoverageID]; owner != u.Owner {
			t.Fatalf("owner %q no coincide con la tarea %q", u.Owner, owner)
		}
	}
}

func TestStoreLockSharedAllowsReadersAndBlocksWriters(t *testing.T) {
	store, _, _ := savedRun(t, "sql-injection")

	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- store.WithSharedLock(context.Background(), 5*time.Second, func() error {
			<-release
			return nil
		})
	}()
	// Un segundo lector debe poder entrar mientras el primero mantiene el
	// bloqueo compartido.
	secondErr := store.WithSharedLock(context.Background(), 2*time.Second, func() error { return nil })
	if secondErr != nil {
		t.Fatalf("lector concurrente rechazado: %v", secondErr)
	}
	if err := store.WithLock(context.Background(), 100*time.Millisecond, func() error { return nil }); err == nil {
		t.Fatal("un escritor no debe entrar mientras hay un lector")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("primer lector: %v", err)
	}
}

func TestStoreLockCanceledWaitDoesNotModifyRun(t *testing.T) {
	store, ledger, _ := savedRun(t, "sql-injection")
	before, err := os.ReadFile(store.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	held, err := platform.Acquire(context.Background(), store.LockPath(), false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.WithRunLock(ctx, time.Second, func() error {
		t.Fatal("el ciclo no debió ejecutarse")
		return nil
	}); err == nil {
		t.Fatal("la espera cancelada debió fallar")
	}
	after, err := os.ReadFile(store.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("una espera cancelada modificó la corrida")
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err := nextCycle(store, "hunter-a"); err != nil {
		t.Fatalf("la corrida quedó inservible tras la cancelación: %v", err)
	}
	_ = ledger
}

func TestWithRunLockWithoutRunCreatesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-existe")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	err = store.WithRunLock(context.Background(), time.Second, func() error {
		t.Fatal("no debió haber ciclo sin corrida")
		return nil
	})
	if !errors.Is(err, ErrNoAudit) {
		t.Fatalf("err = %v, want ErrNoAudit", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Fatalf("el bloqueo creó el directorio de la corrida: %v", statErr)
	}
}
