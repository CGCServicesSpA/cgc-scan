# Hallazgos esperados por fixture

La prueba de integración compara el tipo de hallazgo, no la línea exacta. Un
`fixed` puede conservar hallazgos informativos legítimos; lo que no puede es
conservar el caso vulnerable que el par demuestra.

| Fixture | Caso vulnerable | Motor | `fixed` esperado |
| --- | --- | --- | --- |
| `go/vulnerable` | `golang.org/x/text v0.3.0` con CVEs de dependencia | Trivy, govulncheck | sin vulnerabilidades |
| `javascript/vulnerable` | `eval`, `child_process.exec`, `RegExp` no literal | ESLint | sin hallazgos de las reglas de seguridad |
| `typescript/vulnerable` | `eval` en TSX con parser TypeScript | ESLint | sin hallazgos |
| `php/vulnerable` | taint de `$_GET` a `echo` y `system` | Psalm (requiere `composer install`) | sin taint |
| `rust/vulnerable` | `time 0.1.44` (RUSTSEC-2020-0071) | cargo-audit, Trivy | sin vulnerabilidades |
| `python/vulnerable` | `shell=True`, `eval`, MD5 | Bandit | sin hallazgos |
| `monorepo` | Go + JavaScript + Python en un árbol | Trivy + govulncheck + ESLint + Bandit | — |

Notas de preparación:

- `php/*` requiere `composer install` para que exista `vendor/autoload.php`; sin
  él, Psalm se omite con `requirement_missing` y la ejecución es incompleta.
- `rust/*` ya incluye `Cargo.lock` generado con el manifiesto real.
- La base de Go y el snapshot de RustSec se preparan con `update-db`.
