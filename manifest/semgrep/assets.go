// Package semgrepassets embebe las reglas propias de CGC Scan.
package semgrepassets

import "embed"

//go:embed rules/*.yaml rules/LICENSE
var Rules embed.FS
