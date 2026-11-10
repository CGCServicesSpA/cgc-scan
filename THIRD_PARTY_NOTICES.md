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
| `golang.org/x/vuln` | BSD-3-Clause | govulncheck como biblioteca en modo host |
| `golang.org/x/sys`, `golang.org/x/text`, `golang.org/x/mod`, `golang.org/x/tools`, `golang.org/x/telemetry` | BSD-3-Clause | Dependencias indirectas |

## Motores y herramientas externas

Se descargan o instalan en tiempo de preparación y conservan su propia licencia.
No se enlazan estáticamente con la CLI, salvo `govulncheck` en modo host.

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

## Imágenes base de lenguaje

Con Docker, la CLI descarga la imagen oficial del lenguaje (`golang`, `node`,
`php`, `rust`, `python`) en la versión del proyecto y construye una imagen
derivada. No se redistribuyen con CGC Scan: se obtienen del registro público y
conservan sus licencias y avisos. Las herramientas que se instalan dentro están
fijadas por el manifiesto de confianza o por los lockfiles/requisitos embebidos.

## Material de referencia reutilizado

El protocolo de auditoría (`internal/audit`, `docs/auditoria.md`) y el catálogo
de clases se inspiran en la estructura y las categorías de
[`cloudflare/security-audit-skill`](https://github.com/cloudflare/security-audit-skill),
publicado bajo licencia MIT. No se redistribuye su código ni sus prompts
verbatim: se adaptaron conceptos de cobertura, veredictos y verificación
independiente, y los textos del catálogo son propios.

## Obligaciones

- Conservar este archivo y `LICENSE` en cada distribución.
- Publicar el SBOM CycloneDX con el release.
- No redistribuir reglas del registro público de Semgrep.
- Revisar cada dependencia directa nueva antes de incorporarla y registrarla en
  `design.md` §2.
- Conservar el aviso MIT del material de referencia citado arriba.
