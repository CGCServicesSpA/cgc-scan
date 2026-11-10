package cli

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/CGCServicesSpA/cgc-scan/internal/plan"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

// collectVCS lee metadatos locales de Git, sin operaciones remotas.
func collectVCS(root string) report.VCS {
	v := report.VCS{Available: false}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rev, err := gitOutput(ctx, root, "rev-parse", "HEAD")
	if err != nil || rev == "" {
		return v
	}
	v.Available = true
	v.Revision = rev
	if branch, err := gitOutput(ctx, root, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		v.Branch = branch
	}
	if status, err := gitOutput(ctx, root, "status", "--porcelain", "--untracked-files=all"); err == nil {
		for _, line := range strings.Split(status, "\n") {
			if strings.HasPrefix(line, "??") {
				v.Untracked++
			}
		}
		if strings.TrimSpace(status) != "" {
			v.Dirty = true
		}
	}
	return v
}

func gitOutput(ctx context.Context, root string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// changedUnits devuelve las unidades tocadas desde la revisión de la línea
// base, combinando el diff con el estado local (incluidos no rastreados).
// Si no hay revisión, todas las unidades se consideran cambiadas.
func changedUnits(ctx context.Context, root string, baseline *report.Document) (map[string]bool, string) {
	changed := map[string]bool{}
	revision := ""
	if baseline != nil {
		revision = baseline.Target.VCS.Revision
	}
	paths := map[string]bool{}
	if revision != "" {
		if out, err := gitOutput(ctx, root, "diff", "--name-only", revision, "--", "."); err == nil {
			for _, p := range strings.Split(out, "\n") {
				if p = strings.TrimSpace(p); p != "" {
					paths[p] = true
				}
			}
		}
	}
	if out, err := gitOutput(ctx, root, "status", "--porcelain", "--untracked-files=all"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			if len(line) < 4 {
				continue
			}
			p := strings.TrimSpace(line[3:])
			if i := strings.Index(p, " -> "); i >= 0 {
				p = p[i+4:]
			}
			if p != "" {
				paths[p] = true
			}
		}
	}
	if revision == "" {
		return nil, "sin revisión en la línea base; --changed analiza todas las unidades"
	}
	if len(paths) == 0 {
		return changed, ""
	}
	for p := range paths {
		for _, u := range baseline.Target.Units {
			if u.Path == "" || u.Path == "." {
				continue
			}
			if p == u.Path || strings.HasPrefix(p, u.Path+"/") {
				changed[u.ID] = true
			}
		}
		changed["project"] = true
	}
	// Una unidad solo se incluye si ella o uno de sus archivos cambió. El
	// proyecto siempre entra porque Trivy recorre el árbol completo.
	if len(changed) == 0 {
		for _, u := range baseline.Target.Units {
			changed[u.ID] = true
		}
	}
	return changed, ""
}

// filterPlanUnits recorta el plan y deja constancia en not_analyzed.
func filterPlanUnits(p *plan.Plan, keep map[string]bool, reason string) {
	kept := make([]plan.UnitPlan, 0, len(p.Units))
	for _, u := range p.Units {
		if keep[u.Unit.ID] {
			kept = append(kept, u)
			continue
		}
		p.NotAnalyzed = append(p.NotAnalyzed, plan.NotAnalyzed{
			Unit: u.Unit.ID, Path: u.Unit.Path, Reason: reason,
		})
	}
	p.Units = kept
}
