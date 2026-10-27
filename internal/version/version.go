// Package version expone los metadatos de compilación de la CLI y del esquema.
package version

import (
	"fmt"
	"runtime"
	"strings"
)

// Los valores se inyectan con -ldflags "-X ...". En una compilación de
// desarrollo quedan los valores por defecto, que nunca se presentan como
// versión publicada.
var (
	Version   = "0.0.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// SchemaVersion es la versión del contrato del reporte.
const SchemaVersion = "1.0.0"

// Name es el nombre del binario y del producto.
const Name = "cgc-scan"

// UserAgent identifica la CLI ante los servidores que lo solicitan.
func UserAgent() string {
	return fmt.Sprintf("%s/%s (%s/%s)", Name, Version, runtime.GOOS, runtime.GOARCH)
}

// IsDevelopment informa si la compilación no proviene de un release.
func IsDevelopment() bool {
	return strings.HasSuffix(Version, "-dev") || Version == "" || Version == "0.0.0"
}

// String devuelve la línea de --version, que incluye CLI, esquema y plataforma.
func String() string {
	return fmt.Sprintf("%s %s (commit %s, %s, %s/%s, esquema %s)",
		Name, Version, Commit, BuildDate, runtime.GOOS, runtime.GOARCH, SchemaVersion)
}
