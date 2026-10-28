// Package runner ejecuta motores externos como procesos no confiables: entorno
// mínimo, HOME aislado, grupos de procesos, timeouts y tope de salida
// (design §5.1, §6.4).
package runner

import (
	"context"
	"time"
)

// IsolationLevel es el nivel declarado en el reporte (PRD §6.6).
type IsolationLevel string

const (
	IsolationEnforced   IsolationLevel = "enforced"
	IsolationConfigured IsolationLevel = "configured"
)

// Rank permite comparar niveles: enforced > configured.
func (l IsolationLevel) Rank() int {
	if l == IsolationEnforced {
		return 2
	}
	if l == IsolationConfigured {
		return 1
	}
	return 0
}

// Invocation describe una ejecución concreta.
type Invocation struct {
	Engine string
	Binary string   // ruta absoluta al ejecutable
	Args   []string // nunca pasan por shell
	Dir    string   // directorio de trabajo (vacío = raíz del proyecto)
	// ProjectRO es la raíz del proyecto que el runner Docker monta en /src en
	// solo lectura. El runner global no la usa.
	ProjectRO string
	// Entrypoint sustituye el entrypoint de la imagen (solo runner Docker).
	Entrypoint string
	// Local ejecuta el motor en el proceso actual (bibliotecas, p. ej.
	// govulncheck). Recibe el entorno ya saneado por el runner.
	Local func(ctx context.Context, env []string) (Result, error)
	Env   map[string]string // se suma a la lista permitida base
	// AllowNetwork solo se usa en la fase de preparación (descarga de bases).
	// Durante el escaneo debe ser falso: el proxy apunta a un destino cerrado.
	AllowNetwork bool
	Timeout      time.Duration
	MaxOutput    int64 // tope de bytes de stdout
}

// Result es el resultado de una ejecución, incluso si terminó con error.
type Result struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Duration  time.Duration
	Truncated bool
	TimedOut  bool
	Canceled  bool
}

// Runner es la interfaz que implementan Docker y el runner global.
type Runner interface {
	Kind() string
	Isolation(ctx context.Context) (IsolationLevel, error)
	Run(ctx context.Context, inv Invocation) (Result, error)
}
