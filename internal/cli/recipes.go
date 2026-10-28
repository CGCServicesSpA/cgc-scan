package cli

import (
	"context"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/CGCServicesSpA/cgc-scan/internal/config"
	"github.com/CGCServicesSpA/cgc-scan/internal/discovery"
	"github.com/CGCServicesSpA/cgc-scan/internal/recipes"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func (a *App) runRecipes(_ *cobra.Command, setFile string, clear bool, format string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return IncompleteErrorf("obtener el directorio actual: %v", err)
	}
	root := discovery.DetectRoot(cwd)
	cfg, err := config.Load(a.Paths.ConfigFile())
	if err != nil {
		return UsageErrorf("%v", err)
	}

	switch {
	case clear:
		n := recipes.Clear(&cfg, root)
		if err := config.Save(a.Paths.ConfigFile(), cfg); err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, []byte("Recetas eliminadas: "+strconv.Itoa(n)+"\n"))
	case setFile != "":
		entries, err := recipes.LoadFile(setFile, root)
		if err != nil {
			return UsageErrorf("%v", err)
		}
		recipes.Merge(&cfg, root, entries)
		if err := config.Save(a.Paths.ConfigFile(), cfg); err != nil {
			return IncompleteErrorf("%v", err)
		}
		return report.EmitRaw(a.Stdout, []byte("Recetas confirmadas: "+strconv.Itoa(len(entries))+"\n"))
	}

	disc, err := discovery.Discover(context.Background(), discovery.Options{Target: cwd})
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	listing := recipes.Listing{
		Project:    root,
		Candidates: recipes.Detect(root, disc.Units),
		Confirmed:  recipes.Confirmed(cfg, root),
	}
	var data []byte
	if format == "json" {
		data, err = listing.JSON()
	} else {
		data = []byte(listing.Text())
	}
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	return report.EmitRaw(a.Stdout, data)
}
