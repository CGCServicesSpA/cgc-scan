package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.test",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.test",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestCollectVCSAndChangedUnits(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "svc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "svc", "a.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "other.txt"), []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	git(t, root, "init", "-q")
	git(t, root, "add", ".")
	git(t, root, "commit", "-q", "-m", "inicial")

	vcs := collectVCS(root)
	if !vcs.Available || vcs.Revision == "" || vcs.Dirty {
		t.Fatalf("vcs = %+v", vcs)
	}
	baseline := &report.Document{
		Target: report.Target{
			VCS: report.VCS{Available: true, Revision: vcs.Revision},
			Units: []report.UnitInfo{
				{ID: "project", Path: ".", Kind: "repository"},
				{ID: "svc", Path: "svc", Kind: "module"},
				{ID: "spare", Path: "spare", Kind: "module"},
			},
		},
	}
	if err := os.WriteFile(filepath.Join(root, "svc", "a.txt"), []byte("cambiado"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, note := changedUnits(context.Background(), root, baseline)
	if note != "" || !changed["svc"] || !changed["project"] || changed["spare"] {
		t.Fatalf("cambiadas = %v, nota = %q", changed, note)
	}
	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("u"), 0o600); err != nil {
		t.Fatal(err)
	}
	vcs = collectVCS(root)
	if !vcs.Dirty || vcs.Untracked != 1 {
		t.Fatalf("vcs con no rastreado = %+v", vcs)
	}
}

func TestChangedWithoutRevisionScansAll(t *testing.T) {
	root := t.TempDir()
	git(t, root, "init", "-q")
	doc := &report.Document{Target: report.Target{Units: []report.UnitInfo{{ID: "project", Path: "."}}}}
	changed, note := changedUnits(context.Background(), root, doc)
	if changed != nil || note == "" {
		t.Fatalf("cambiadas = %v, nota = %q", changed, note)
	}
}
