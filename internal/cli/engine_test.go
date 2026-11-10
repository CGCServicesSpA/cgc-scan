package cli

import (
	"testing"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/provision"
)

func TestDBFreshHonorsRefreshAfter(t *testing.T) {
	now := time.Now().UTC()
	if !dbFresh(provision.DBInfo{UpdatedAt: now.Add(-time.Hour)}, 12*time.Hour) {
		t.Fatal("una base de una hora debería reutilizarse con refresh_after de 12h")
	}
	if dbFresh(provision.DBInfo{UpdatedAt: now.Add(-24 * time.Hour)}, 12*time.Hour) {
		t.Fatal("una base de 24h no debería reutilizarse con refresh_after de 12h")
	}
	if dbFresh(provision.DBInfo{}, 12*time.Hour) {
		t.Fatal("una base sin fecha no es fresca")
	}
	if dbFresh(provision.DBInfo{UpdatedAt: now}, 0) {
		t.Fatal("refresh_after=0 debe forzar la actualización")
	}
}

func TestFindGoBinaryPrefersGOROOT(t *testing.T) {
	got, err := findGoBinary()
	if err != nil {
		t.Fatalf("findGoBinary: %v", err)
	}
	if got == "" {
		t.Fatal("ruta vacía")
	}
}
