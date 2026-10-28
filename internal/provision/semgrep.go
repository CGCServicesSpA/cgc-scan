package provision

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	semgrepassets "github.com/CGCServicesSpA/cgc-scan/manifest/semgrep"
)

var semverThree = regexp.MustCompile(`([0-9]+\.[0-9]+\.[0-9]+)`)

// WriteSemgrepRules copia las reglas embebidas a un directorio privado y
// devuelve cuántas reglas escribió. Se ejecuta en la preparación, nunca dentro
// del proyecto.
func WriteSemgrepRules(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	count := 0
	err := fs.WalkDir(semgrepassets.Rules, "rules", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := semgrepassets.Rules.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(p)), data, 0o600); err != nil {
			return err
		}
		if strings.HasSuffix(p, ".yaml") {
			count++
		}
		return nil
	})
	return count, err
}

// VerifySemgrepVersion comprueba que el binario responde con la versión fijada.
func VerifySemgrepVersion(ctx context.Context, binary, want string) error {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, binary, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("semgrep --version: %w", err)
	}
	got := semverThree.FindString(string(out))
	if got != want {
		return fmt.Errorf("semgrep instalado es %s y se requiere %s", got, want)
	}
	return nil
}
