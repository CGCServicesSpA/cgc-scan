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

## Ejecución en contenedores de toolchain (v1.2)

Revisión específica de RF-38 / ADR-18:

- La versión se acepta solo si es numérica y con puntos (`versionish`); nunca se
  interpola texto del proyecto en una referencia de imagen.
- La imagen base se resuelve por digest y se registra; la etiqueta derivada es
  determinista. La herramienta sigue fijada por versión y hash en el manifiesto.
- El build no ejecuta scripts del proyecto: `npm ci --ignore-scripts`, pip con
  hashes, artefactos con SHA-256 y `GOTOOLCHAIN=auto` para compilar govulncheck.
- El proyecto se monta en solo lectura; las bases y la configuración de Psalm se
  montan desde un staging temporal que se elimina al terminar. La CLI no escribe
  en el proyecto.
- Cada lenguaje usa un volumen `cgc-scan-toolchain-*` propio del uid; la caché
  incremental incluye imagen, entorno y destino de los montajes.
- La red del contenedor de toolchain es intencional y declarada `configured`;
  `--offline` usa `--network none`. Un fallo de build no produce un resultado
  limpio: cae al host o queda `requirement_missing`.
- Riesgo residual: la resolución de dependencias revela nombres y versiones al
  registro público del ecosistema, nunca código ni secretos. Se documenta en
  `docs/privacidad.md` y en la limitación del reporte.

## Riesgos residuales aceptados

| Riesgo | Mitigación | Estado |
| --- | --- | --- |
| `configured` no es un sandbox | Reporte declara el nivel; `--require-isolation enforced` para el nivel fuerte | Aceptado |
| Contenedor Trivy como root | Volumen propio del uid, sin código, `--read-only`, sin red | Aceptado (ADR-13) |
| Contenedor de toolchain como root y con red | Proyecto en solo lectura, caché en volumen propio del uid, red solo para resolver dependencias, aislamiento declarado `configured` | Aceptado (ADR-18) |
| Dependencias del proyecto visibles al registro público | El contenedor de toolchain resuelve dependencias contra el registro del ecosistema; se exponen nombres y versiones, nunca código ni secretos. `--offline` y `CGC_SCAN_TOOLCHAIN=host` lo evitan; el reporte lo declara | Aceptado y documentado |
| Imagen base de toolchain no fijada en el manifiesto | Se resuelve por digest al construir y el digest queda en `tools.engines[].preparation[]`; la herramienta sí está fijada por versión y hash | Aceptado (ADR-18) |
| Pertenecer a `docker` equivale a root en el host | Fuera del modelo: es una decisión del usuario | Documentado |
| Base de Trivy ~1,6 GB | Timeout de preparación y volumen persistente | Aceptado |
| Toolchains del proyecto en el host | Con Docker se evita; sin Docker, `requirement_missing` y código 3 | Aceptado |
| Firma/SBOM sin release real | Flujo configurado; pendiente CA-54 | Abierto |
| Marca INAPI | Búsqueda manual pendiente (H7-06) | Abierto |

## Conclusión

No quedan hallazgos críticos o altos abiertos en el código de la CLI. Los puntos
abiertos son de proceso de release y legales, no de implementación. La
ejecución en contenedores de toolchain (RF-38) deja un riesgo residual acotado y
declarado: la resolución de dependencias revela nombres y versiones al registro
público, nunca código ni secretos; `--offline` y `CGC_SCAN_TOOLCHAIN=host` son
las salidas documentadas.
