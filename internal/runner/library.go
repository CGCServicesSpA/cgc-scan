package runner

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Library ejecuta motores enlazados como biblioteca en el proceso actual. Usa
// el mismo entorno saneado y el mismo timeout que el runner global, pero no
// crea un proceso hijo (ADR-14).
type Library struct {
	Global *Global
}

// Kind identifica el runner en el reporte.
func (l *Library) Kind() string { return "library" }

// Isolation declara el nivel configured: la biblioteca no abre red por sí
// misma y el entorno le cierra el proxy.
func (l *Library) Isolation(context.Context) (IsolationLevel, error) {
	return IsolationConfigured, nil
}

// Run ejecuta inv.Local con el entorno saneado.
func (l *Library) Run(ctx context.Context, inv Invocation) (Result, error) {
	if inv.Local == nil {
		return Result{}, fmt.Errorf("runner library: %s no define una función local", inv.Engine)
	}
	if l.Global == nil {
		return Result{}, errors.New("runner library: falta la configuración de entorno")
	}
	env, err := l.Global.buildEnv(inv)
	if err != nil {
		return Result{}, err
	}
	timeout := inv.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	res, err := inv.Local(runCtx, env)
	res.Duration = time.Since(start)
	if res.Canceled || res.TimedOut {
		return res, err
	}
	res.Canceled = ctx.Err() != nil
	res.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	if err != nil {
		return res, err
	}
	return res, nil
}
