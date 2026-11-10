package provision

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoVulnIncrementalMirror(t *testing.T) {
	var idRequests int32
	var vulns []map[string]string
	vulns = []map[string]string{
		{"id": "GO-2024-0001", "modified": "2026-01-01T00:00:00Z"},
		{"id": "GO-2024-0002", "modified": "2026-01-01T00:00:00Z"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index/modules.json":
			fmt.Fprint(w, `{"path":"example.com/m"}`)
		case "/index/vulns.json":
			_ = json.NewEncoder(w).Encode(vulns)
		default:
			atomic.AddInt32(&idRequests, 1)
			fmt.Fprint(w, `{"id":"x"}`)
		}
	}))
	defer srv.Close()
	old := goVulnBase
	goVulnBase = srv.URL
	defer func() { goVulnBase = old }()

	dir := filepath.Join(t.TempDir(), "go-vulndb")
	ctx := context.Background()
	info, err := EnsureGoVulnDBWithRefresh(ctx, srv.Client(), dir, false, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if info.Status != "updated" || atomic.LoadInt32(&idRequests) != 2 {
		t.Fatalf("inicial = %+v, ids=%d", info, idRequests)
	}

	// Dentro de refresh_after no se consulta la red.
	before := atomic.LoadInt32(&idRequests)
	info, err = EnsureGoVulnDBWithRefresh(ctx, srv.Client(), dir, false, 12*time.Hour)
	if err != nil || info.Status != "reused" || atomic.LoadInt32(&idRequests) != before {
		t.Fatalf("reutilización = %+v, ids=%d", info, idRequests)
	}

	// Con refresh vencido se actualiza el índice pero no se rebajan avisos.
	info, err = EnsureGoVulnDBWithRefresh(ctx, srv.Client(), dir, false, 0)
	if err != nil || info.Status != "updated" || atomic.LoadInt32(&idRequests) != 2 {
		t.Fatalf("sin cambios = %+v, ids=%d", info, idRequests)
	}

	// Solo se descarga el aviso modificado.
	vulns[1]["modified"] = "2026-02-01T00:00:00Z"
	if _, err := EnsureGoVulnDBWithRefresh(ctx, srv.Client(), dir, false, 0); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&idRequests); got != 3 {
		t.Fatalf("descargas = %d, want 3", got)
	}

	// Un aviso retirado del índice se elimina del espejo.
	vulns = vulns[:1]
	if _, err := EnsureGoVulnDBWithRefresh(ctx, srv.Client(), dir, false, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ID", "GO-2024-0002.json")); !os.IsNotExist(err) {
		t.Fatalf("aviso retirado sigue presente: %v", err)
	}
}
