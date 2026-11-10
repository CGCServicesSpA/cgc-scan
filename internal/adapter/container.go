package adapter

import (
	"path/filepath"
	"strings"

	"github.com/CGCServicesSpA/cgc-scan/internal/runner"
)

// ContainerRoot es la ruta en la que el runner Docker monta el proyecto.
const ContainerRoot = "/src"

// Container describe la imagen de toolchain en la que se ejecuta un adaptador
// para una unidad concreta. Lo construye la CLI a partir de la versión que
// declara el proyecto y de la imagen derivada correspondiente.
type Container struct {
	// Image es la etiqueta de la imagen derivada, p. ej.
	// cgc-scan/toolchain:go1.22-govulncheck-1.9.0.
	Image string
	// Root es la ruta del proyecto dentro del contenedor. El runner monta el
	// proyecto en solo lectura en esta ruta y fija el directorio de trabajo.
	Root string
	// Mounts son montajes adicionales de la invocación: bases locales en solo
	// lectura y el volumen de caché del lenguaje.
	Mounts []runner.Mount
	// CacheDir es la ruta de la caché escribible del lenguaje (normalmente
	// /cache).
	CacheDir string
	// Offline indica que el contenedor no puede usar red (--offline).
	Offline bool
}

// UnitDir traduce la ruta relativa de una unidad a la ruta del contenedor.
func (c *Container) UnitDir(unitPath string) string {
	root := strings.TrimSuffix(c.Root, "/")
	unitPath = strings.TrimPrefix(filepath.ToSlash(unitPath), "./")
	if unitPath == "" || unitPath == "." {
		return root
	}
	return root + "/" + unitPath
}

// ContainerPath traduce una ruta absoluta del contenedor a una ruta relativa
// al proyecto. Devuelve ok=false si la ruta no pertenece al proyecto montado.
func ContainerPath(containerRoot, p string) (string, bool) {
	root := strings.TrimSuffix(filepath.ToSlash(containerRoot), "/")
	p = filepath.ToSlash(p)
	if root == "" {
		return "", false
	}
	if p == root {
		return ".", true
	}
	if !strings.HasPrefix(p, root+"/") {
		return "", false
	}
	return strings.TrimPrefix(p, root+"/"), true
}

// RelativePath convierte una ruta reportada por un motor a una ruta relativa
// al proyecto. Prefiere la ruta del host (runner global) y cae en la ruta del
// contenedor cuando el motor corrió en una imagen de toolchain.
func RelativePath(hostRoot, containerRoot, p string) string {
	if p == "" {
		return "."
	}
	abs := p
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(hostRoot, p)
	}
	if rel, err := filepath.Rel(hostRoot, abs); err == nil {
		rel = filepath.ToSlash(rel)
		if rel != ".." && !strings.HasPrefix(rel, "../") {
			return rel
		}
	}
	if rel, ok := ContainerPath(containerRoot, p); ok {
		return rel
	}
	return filepath.ToSlash(p)
}
