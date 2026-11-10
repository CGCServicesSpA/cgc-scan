package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/audit"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/policy"
)

// TestMain desvía el binario de pruebas hacia el modo ayudante cuando se lo
// pide el entorno: así la exclusión mutua se prueba con procesos reales, no
// solo con goroutines.
func TestMain(m *testing.M) {
	if os.Getenv("CGC_AUDIT_HELPER") != "" {
		os.Exit(runAuditHelper())
	}
	os.Exit(m.Run())
}

func runAuditHelper() int {
	paths := platform.Paths{
		ConfigDir: os.Getenv("CGC_AUDIT_HELPER_CONFIG"),
		DataDir:   os.Getenv("CGC_AUDIT_HELPER_DATA"),
		CacheDir:  os.Getenv("CGC_AUDIT_HELPER_CACHE"),
	}
	app, err := New(os.Stdout, os.Stderr, WithPaths(paths), WithTTY(false))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	runDir := os.Getenv("CGC_AUDIT_HELPER_RUN")
	switch os.Getenv("CGC_AUDIT_HELPER_MODE") {
	case "next":
		return app.Execute(context.Background(), []string{
			"audit", "next", "--out", runDir,
			"--agent", os.Getenv("CGC_AUDIT_HELPER_AGENT"),
			"--max-units", "1", "--format", "json",
		})
	case "submit":
		return app.Execute(context.Background(), []string{
			"audit", "submit", "--out", runDir,
			"--file", os.Getenv("CGC_AUDIT_HELPER_FILE"), "--format", "json",
		})
	case "hold":
		store, err := audit.OpenStore(runDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		lock, err := platform.Acquire(context.Background(), store.LockPath(), false, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		defer lock.Release()
		fmt.Println("held")
		time.Sleep(2 * time.Second)
		return 0
	}
	fmt.Fprintln(os.Stderr, "modo de ayudante desconocido")
	return 2
}

func helperEnv(tmp, runDir, mode, agent string) []string {
	return append(os.Environ(),
		"CGC_AUDIT_HELPER=1",
		"CGC_AUDIT_HELPER_MODE="+mode,
		"CGC_AUDIT_HELPER_RUN="+runDir,
		"CGC_AUDIT_HELPER_AGENT="+agent,
		"CGC_AUDIT_HELPER_CONFIG="+filepath.Join(tmp, "config"),
		"CGC_AUDIT_HELPER_DATA="+filepath.Join(tmp, "data"),
		"CGC_AUDIT_HELPER_CACHE="+filepath.Join(tmp, "cache"),
	)
}

func TestAuditConcurrentProcessesSerialize(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root,
		"--out", runDir, "--format", "json", "--budget", "50"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}

	const helpers = 6
	type outcome struct {
		code int
		task *audit.Task
	}
	codes := make([]int, helpers)
	tasks := make([]*audit.Task, helpers)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < helpers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			agent := fmt.Sprintf("hunter-%c", 'a'+i)
			taskFile := filepath.Join(tmp, fmt.Sprintf("task-%d.json", i))
			f, err := os.Create(taskFile)
			if err != nil {
				t.Error(err)
				return
			}
			cmd := exec.Command(os.Args[0])
			cmd.Env = helperEnv(tmp, runDir, "next", agent)
			cmd.Stdout = f
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			runErr := cmd.Run()
			f.Close()
			codes[i] = exitCode(t, cmd, runErr, stderr.String())
			if data, rerr := os.ReadFile(taskFile); rerr == nil {
				var task audit.Task
				if json.Unmarshal(data, &task) == nil && task.Kind == "hunt" {
					tasks[i] = &task
				}
			}
		}(i)
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed > 60*time.Second {
		t.Fatalf("los procesos esperaron demasiado: %v", elapsed)
	}

	assigned := map[string]string{}
	for i := range tasks {
		if tasks[i] == nil {
			if codes[i] != 0 {
				t.Fatalf("ayudante %d = %d sin tarea", i, codes[i])
			}
			continue
		}
		if codes[i] != 0 {
			t.Fatalf("ayudante %d = %d con tarea", i, codes[i])
		}
		agent := tasks[i].AgentID
		if len(tasks[i].Units) != 1 {
			t.Fatalf("tarea con %d unidades: %+v", len(tasks[i].Units), tasks[i].Units)
		}
		id := tasks[i].Units[0].Unit.CoverageID
		if other, dup := assigned[id]; dup {
			t.Fatalf("la unidad %s se asignó a %s y %s", id, other, agent)
		}
		assigned[id] = agent
	}
	if len(assigned) == 0 {
		t.Fatal("ningún proceso recibió unidades")
	}

	// Cada agente entrega su cobertura en paralelo: ninguna entrega se pierde.
	var submitWG sync.WaitGroup
	for i := range tasks {
		if tasks[i] == nil {
			continue
		}
		submitWG.Add(1)
		go func(task *audit.Task) {
			defer submitWG.Done()
			file := writeSubmissionFile(t, coveredSubmission(task.AgentID, *task))
			cmd := exec.Command(os.Args[0])
			cmd.Env = helperEnv(tmp, runDir, "submit", task.AgentID)
			cmd.Env = append(cmd.Env, "CGC_AUDIT_HELPER_FILE="+file)
			var out, errOut bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errOut
			if runErr := cmd.Run(); exitCode(t, cmd, runErr, errOut.String()) != 0 {
				t.Errorf("submit de %s = %s %s", task.AgentID, out.String(), errOut.String())
			}
		}(tasks[i])
	}
	submitWG.Wait()

	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := store.LoadLedger()
	if err != nil {
		t.Fatalf("releer ledger: %v", err)
	}
	if ledger.Budget.Used != len(assigned) {
		t.Fatalf("presupuesto usado = %d, want %d", ledger.Budget.Used, len(assigned))
	}
	for _, u := range ledger.Units {
		if owner, wasAssigned := assigned[u.CoverageID]; wasAssigned {
			if u.State != audit.StateCovered || u.Owner != owner || u.Wave != 1 {
				t.Fatalf("unidad asignada mal sellada: %+v", u)
			}
			if len(u.Checks) == 0 {
				t.Fatalf("la entrega de %s se perdió: %+v", owner, u)
			}
		}
	}
}

func exitCode(t *testing.T, cmd *exec.Cmd, runErr error, stderr string) int {
	t.Helper()
	if runErr == nil {
		return 0
	}
	if _, ok := runErr.(*exec.ExitError); ok {
		return cmd.ProcessState.ExitCode()
	}
	t.Fatalf("ayudante no arrancó: %v %s", runErr, stderr)
	return -1
}

func TestAuditCanceledWaitDoesNotModifyRun(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
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
	code := app.Execute(ctx, []string{"audit", "next", "--out", runDir, "--agent", "hunter-a", "--format", "json"})
	if code != policy.ExitCanceled {
		t.Fatalf("código = %d, want %d (cancelada)", code, policy.ExitCanceled)
	}
	after, err := os.ReadFile(store.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("una espera cancelada modificó la corrida")
	}
}

func TestAuditStatusUsesSharedLock(t *testing.T) {
	app, _, _ := newTestApp(t)
	root := auditProject(t)
	runDir := filepath.Join(t.TempDir(), "run")
	if code, out, errOut := auditRun(t, app, "audit", "init", root, "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("init = %d: %s %s", code, out, errOut)
	}
	store, err := audit.OpenStore(runDir)
	if err != nil {
		t.Fatal(err)
	}
	// Un lector externo con el bloqueo compartido no impide `status`.
	held, err := platform.Acquire(context.Background(), store.LockPath(), true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := auditRun(t, app, "audit", "status", "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("status = %d: %s %s", code, out, errOut)
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}

	// Un escritor externo (otro proceso) sí lo impide: status no muta bajo
	// contención. El ayudante retiene el bloqueo exclusivo dos segundos.
	cmd := exec.Command(os.Args[0])
	cmd.Env = helperEnv(t.TempDir(), runDir, "hold", "")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(pipe).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "held" {
		t.Fatalf("el ayudante no tomó el bloqueo: %q %v %s", line, err, stderr.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if code := app.Execute(ctx, []string{"audit", "status", "--out", runDir, "--format", "json"}); code == 0 {
		t.Fatal("status entró mientras un escritor mantenía el bloqueo")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("ayudante: %v (%s)", err, stderr.String())
	}
	// Cuando el escritor suelta el bloqueo, status vuelve a entrar.
	if code, out, errOut := auditRun(t, app, "audit", "status", "--out", runDir, "--format", "json"); code != 0 {
		t.Fatalf("status tras soltar = %d: %s %s", code, out, errOut)
	}
}
