// Command cgc-scan es la CLI de análisis de seguridad local de CGC Services.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/CGCServicesSpA/cgc-scan/internal/cli"
)

func main() {
	os.Exit(run())
}

// run concentra la ejecución y devuelve el código de salida. os.Exit se llama
// una sola vez, en main, para que los defer de la CLI se ejecuten siempre.
func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app, err := cli.New(os.Stdout, os.Stderr)
	if err != nil {
		_, _ = os.Stderr.WriteString("cgc-scan: " + err.Error() + "\n")
		return 3
	}
	return app.Execute(ctx, os.Args[1:])
}
