package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/policy"
)

// ExitError asocia un error a un código de salida estable. main lo traduce a
// os.Exit una sola vez.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("error con código %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error { return e.Err }

// Errorf construye un ExitError con formato.
func Errorf(code int, format string, args ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}

// UsageErrorf marca un error de argumentos o configuración (código 2).
func UsageErrorf(format string, args ...any) error {
	return Errorf(policy.ExitUsage, format, args...)
}

// IncompleteErrorf marca una ejecución incompleta o fallida (código 3).
func IncompleteErrorf(format string, args ...any) error {
	return Errorf(policy.ExitIncomplete, format, args...)
}

// CodeOf devuelve el código de salida de un error. Un error sin clasificar se
// considera ejecución incompleta (3), nunca éxito. Un error de uso de la CLI
// generado por el parser se clasifica como 2.
func CodeOf(err error) int {
	if err == nil {
		return policy.ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	if isUsageError(err) {
		return policy.ExitUsage
	}
	return policy.ExitIncomplete
}

// isUsageError reconoce los errores que produce el parser de flags/comandos de
// cobra antes de ejecutar nada. Se comparan mensajes estables de cobra/pflag;
// nuestros propios errores de uso siempre usan ExitError.
func isUsageError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errUsageSentinel) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, prefix := range []string{
		"unknown command",
		"unknown flag",
		"unknown shorthand flag",
		"flag needs an argument",
		"flag provided but not defined",
		"invalid argument",
		"accepts at most",
		"accepts between",
		"requires at least",
		"requires exactly",
		"must be one of",
	} {
		if strings.HasPrefix(msg, prefix) || strings.Contains(msg, ": "+prefix) {
			return true
		}
	}
	return false
}

var errUsageSentinel = errors.New("uso inválido")

// Fprint writes to w ignoring the error; se usa solo para mensajes de ayuda.
func Fprint(w io.Writer, s string) { _, _ = io.WriteString(w, s) }
