# Avisos de terceros

CGC Scan se distribuye bajo Apache-2.0. Este archivo enumera las dependencias
directas e indirectas relevantes y su licencia. Los textos completos están en
los módulos originales y en el SBOM del release.

## Dependencias Go

| Módulo | Licencia | Uso |
| --- | --- | --- |
| `github.com/spf13/cobra` | Apache-2.0 | Comandos, ayuda y completado |
| `github.com/spf13/pflag` | BSD-3-Clause | Flags de cobra |
| `github.com/inconshreveable/mousetrap` | Apache-2.0 | Soporte de cobra en Windows |
| `github.com/pelletier/go-toml/v2` | MIT | Configuración y política TOML |
| `github.com/gofrs/flock` | BSD-3-Clause | Bloqueos de archivo |
| `github.com/bmatcuk/doublestar/v4` | MIT | Patrones con `**` |
| `github.com/santhosh-tekuri/jsonschema/v6` | Apache-2.0 | Validación del esquema |
| `github.com/google/go-cmp` | BSD-3-Clause | Comparación en pruebas |
| `github.com/rogpeppe/go-internal` | BSD-3-Clause | `testscript` |
| `golang.org/x/sync` | BSD-3-Clause | `errgroup` |
| `golang.org/x/vuln` | BSD-3-Clause | govulncheck como biblioteca |
| `golang.org/x/sys`, `golang.org/x/text`, `golang.org/x/mod`, `golang.org/x/tools`, `golang.org/x/telemetry` | BSD-3-Clause | Dependencias indirectas |

## Motores y herramientas externas

Se descargan o instalan en tiempo de preparación y conservan su propia licencia.
No se enlazan estáticamente con la CLI, salvo `govulncheck`.

| Componente | Licencia |
| --- | --- |
| Trivy | Apache-2.0 |
| ESLint | MIT |
| eslint-plugin-security | Apache-2.0 |
| @typescript-eslint/parser / TypeScript | MIT / Apache-2.0 |
| Psalm | MIT |
| cargo-audit / RustSec | MIT OR Apache-2.0 |
| Bandit | Apache-2.0 |
| Semgrep CE | LGPL-2.1 |
| Reglas propias de CGC | Apache-2.0 |

## Obligaciones

- Conservar este archivo y `LICENSE` en cada distribución.
- Publicar el SBOM CycloneDX con el release.
- No redistribuir reglas del registro público de Semgrep.
- Revisar cada dependencia directa nueva antes de incorporarla y registrarla en
  `design.md` §2.
