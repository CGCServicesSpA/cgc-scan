// Package banditassets embebe las dependencias fijadas de Bandit.
package banditassets

import _ "embed"

//go:embed requirements.txt
var Requirements []byte
