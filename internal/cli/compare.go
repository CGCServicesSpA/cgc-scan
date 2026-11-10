package cli

import (
	"context"
	"errors"
	"io"
	"path/filepath"

	"github.com/CGCServicesSpA/cgc-scan/internal/compare"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
	"github.com/CGCServicesSpA/cgc-scan/internal/projectstate"
	"github.com/CGCServicesSpA/cgc-scan/internal/report"
)

func (a *App) runCompare(_ context.Context, previousPath, currentPath, format string) error {
	previous, err := loadReport(previousPath)
	if err != nil {
		return UsageErrorf("reporte anterior: %v", err)
	}
	current, err := loadReport(currentPath)
	if err != nil {
		return UsageErrorf("reporte actual: %v", err)
	}
	return emitCompare(previous, current, format, a.Stdout)
}

func (a *App) runCompareBaseline(target, format string) error {
	store, err := a.projectStore(target)
	if err != nil {
		return err
	}
	baseline, err := store.LoadBaseline()
	if err != nil {
		if errors.Is(err, projectstate.ErrNoBaseline) {
			return IncompleteErrorf("%v", err)
		}
		return IncompleteErrorf("%v", err)
	}
	current, err := store.LoadLatest()
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	return emitCompare(baseline, current, format, a.Stdout)
}

func emitCompare(previous, current *report.Document, format string, w io.Writer) error {
	res := compare.Compare(previous, current)
	var data []byte
	var err error
	if format == "json" {
		data, err = res.JSON()
	} else {
		data = []byte(res.Text())
	}
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	return report.EmitRaw(w, data)
}

func loadReport(path string) (*report.Document, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := platform.ReadFileBounded(abs, 64<<20)
	if err != nil {
		return nil, err
	}
	if err := report.Validate(data); err != nil {
		return nil, err
	}
	return report.Decode(data)
}
