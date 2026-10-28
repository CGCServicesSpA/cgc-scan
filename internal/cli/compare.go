package cli

import (
	"context"
	"path/filepath"

	"github.com/CGCServicesSpA/cgc-scan/internal/compare"
	"github.com/CGCServicesSpA/cgc-scan/internal/platform"
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
	res := compare.Compare(previous, current)
	var data []byte
	if format == "json" {
		data, err = res.JSON()
	} else {
		data = []byte(res.Text())
	}
	if err != nil {
		return IncompleteErrorf("%v", err)
	}
	return report.EmitRaw(a.Stdout, data)
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
