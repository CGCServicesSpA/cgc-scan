package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
)

// BenchmarkBuildLedgerMonorepo mide la construcción del ledger en un fixture
// de monorepo: descubrimiento y reparto por perfil.
func BenchmarkBuildLedgerMonorepo(b *testing.B) {
	cat, err := LoadCatalog()
	if err != nil {
		b.Fatal(err)
	}
	// El fixture de monorepo del repositorio, preparado en un directorio de
	// trabajo por corrida del benchmark.
	root := prepareMonorepo(b)
	for _, profile := range []string{ProfileQuick, ProfileStandard, ProfileDeep} {
		b.Run(profile, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				res, err := discovery.Discover(context.Background(), discovery.Options{Target: root})
				if err != nil {
					b.Fatal(err)
				}
				if _, err := BuildLedger(BuildOptions{
					Catalog: cat, Discovery: res, Profile: profile,
					RunID: "run-bench", Now: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC),
					CLIVersion: "test", SourceRef: "rev-1",
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// prepareMonorepo copia el fixture de monorepo a un directorio temporal.
func prepareMonorepo(b *testing.B) string {
	b.Helper()
	root := b.TempDir()
	if err := copyDir("../../testdata/fixtures/monorepo", root); err != nil {
		b.Fatal(err)
	}
	return root
}

// copyDir copia recursivamente un árbol de fixture.
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyDir(s, d); err != nil {
				return err
			}
			continue
		}
		data, err := os.ReadFile(s)
		if err != nil {
			return err
		}
		if err := os.WriteFile(d, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
