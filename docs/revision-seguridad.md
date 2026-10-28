# Revisión de seguridad de CGC Scan

> Revisión interna contra el modelo de amenazas de `design.md` §13. No sustituye
> una auditoría externa.

## Método

- Revisión del código y del modelo de amenazas.
- `golangci-lint` con `gosec`, `errcheck`, `forbidigo`, `staticcheck` y `revive`.
- `govulncheck` sobre la propia CLI con base local.
- Pruebas de aislamiento con `strace` (Trivy y control negativo).
- Ejecución real de los seis adaptadores sobre fixtures vulnerable/corregido.
- Pruebas de contrato contra el esquema y fuzzing de todos los parsers.

## Hallazgos corregidos durante la construcción

| ID | Hallazgo | Impacto | Corrección |
| --- | --- | --- | --- |
| S-01 | Trivy abría `check.trivy.dev` aun con las opciones offline | El nivel `configured` era falso | `--skip-version-check` obligatorio y prueba de aislamiento |
| S-02 | El proxy inválido también bloqueaba la descarga de bases | Preparación imposible | `AllowNetwork` solo en preparación; el escaneo sigue cerrado |
| S-03 | Un escaneo de una subcarpeta de un repo Git analizaba todo el repo | Cobertura y resultados engañosos | El objetivo es el universo; la raíz solo enumera lo no analizado |
| S-04 | Bloqueo exclusivo seguido de compartido se autobloqueaba | Escaneo colgado | Liberar el exclusivo antes de pedir el compartido |
| S-05 | Bandit incluía el valor del secreto en `issue_text` y en el código | Fuga de credenciales | Enmascarado cruzado de los valores detectados por B105-B107 |
| S-06 | Semgrep fallaba sin HOME escribible en el contenedor | Tercer nivel inoperante | `HOME=/tmp` sobre tmpfs efímero |
| S-07 | Psalm no resolvía `ignoreFiles` inexistentes | Fallo de configuración | Solo se emiten rutas existentes |
| S-08 | Las rutas de los motores no eran comparables entre sí | Huellas y `compare` inconsistentes | Normalización a rutas relativas a la raíz y recálculo de huella |

## Controles verificados

- Entorno por lista permitida y HOME aislado; sin herencia de tokens.
- Proyecto en solo lectura; `os.Root` para enlaces y `..`.
- Lista de claves permitidas en la política del proyecto; nunca debilita el umbral.
- Sin ejecución de hooks, scripts de instalación ni configuración del repositorio.
- Tope de salida, timeout, cancelación y terminación del grupo de procesos.
- Secretos enmascarados; permisos 0600/0700; salidas originales enmascaradas.
- Manifiesto de confianza, SHA-256, extracción segura y bloqueo de instalación.
- Prompt con nonce, saneado de control/ANSI/bidi y datos no confiables delimitados.

## Riesgos residuales aceptados

| Riesgo | Mitigación | Estado |
| --- | --- | --- |
| `configured` no es un sandbox | Reporte declara el nivel; `--require-isolation enforced` para el nivel fuerte | Aceptado |
| Contenedor Trivy como root | Volumen propio del uid, sin código, `--read-only`, sin red | Aceptado (ADR-13) |
| Pertenecer a `docker` equivale a root en el host | Fuera del modelo: es una decisión del usuario | Documentado |
| Base de Trivy ~1,6 GB | Timeout de preparación y volumen persistente | Aceptado |
| Toolchains del proyecto no se instalan | `requirement_missing` y código 3 | Aceptado |
| Firma/SBOM sin release real | Flujo configurado; pendiente CA-54 | Abierto |
| Marca INAPI | Búsqueda manual pendiente (H7-06) | Abierto |

## Conclusión

No quedan hallazgos críticos o altos abiertos en el código de la CLI. Los puntos
abiertos son de proceso de release y legales, no de implementación.
