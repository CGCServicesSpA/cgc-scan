// Package eslintassets embebe el árbol fijado de ESLint usado por el
// aprovisionamiento verificado.
package eslintassets

import _ "embed"

//go:embed package.json
var PackageJSON []byte

//go:embed package-lock.json
var LockJSON []byte

//go:embed cgc-eslint.config.mjs
var Config []byte
