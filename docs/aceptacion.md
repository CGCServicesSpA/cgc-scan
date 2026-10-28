# Matriz de aceptación

> Registro de la revisión de los criterios CA-01 a CA-58 del PRD (v0.10).
> **Verificado** = hay una prueba automatizada o una ejecución real registrada.
> **Parcial** = el mecanismo existe y está probado en parte, pero falta una
> condición de entorno. **Pendiente** = no se puede cerrar sin un release real.
>
> La verificación completa y repetible es H7-04; este documento se actualiza al
> cerrar cada criterio.

| CA | Resultado | Evidencia |
| --- | --- | --- |
| CA-01 | Verificado | `TestFixturesVulnerableAndFixedIntegration`: pares de los seis lenguajes con motores reales |
| CA-02 | Verificado | Monorepo mixto con unidad de proyecto y tres unidades; `coverage.units` con estado |
| CA-03 | Verificado | P-09: `strace` con cero `connect`; workflow `isolation.yml` |
| CA-04 | Verificado | Sin runtime, credenciales ni SDK de IA; `go.mod` sin dependencias de inferencia |
| CA-05 | Verificado | `--ai` y `analyze` devuelven 2 (`TestUnsupportedAIFlagsAreUsageErrors`) |
| CA-06 | Verificado | `requirement_missing` en PHP sin `vendor/`; adaptador omitido y código 3 |
| CA-07 | Verificado | Correlación conserva fuentes y diferencias (`severity_others`) |
| CA-08 | Verificado | JSON validado contra el esquema; logs a stderr |
| CA-09 | Verificado | `TestComparePartialDoesNotResolve` y `not_evaluated` |
| CA-10 | Verificado | Timeout/cancelación terminan el grupo de procesos; código 130 |
| CA-11 | Verificado | Hash del árbol antes/después en los fixtures |
| CA-12 | Verificado | Excepción vencida deja de suprimir y conserva motivo |
| CA-13 | Verificado | Secretos de Trivy y Bandit enmascarados; fuzz de `Redact` |
| CA-14 | Verificado | Política hostil ignorada; prompt sanea ANSI/bidi y usa nonce |
| CA-15 | Verificado | Prompt renderiza el mismo documento; no hay inferencia |
| CA-16 | Verificado | Plantilla exige parche → tests → build → reescaneo |
| CA-17 | Verificado | Regla explícita de detener ante adaptación de tests por major |
| CA-18 | Verificado | Regla de no modificar ni omitir tests; bloqueo si fallan |
| CA-19 | Verificado | Unidades sin receta declaradas como bloqueadas |
| CA-20 | Verificado | `TestPromptSanitizesHostileEvidence` y contador de delimitadores |
| CA-21 | Verificado | `TestPromptNoFindings`: no inventa parches ni promete ausencia |
| CA-22 | Verificado | `--report-out` atómico y equivalente; error de escritura no declara éxito |
| CA-23 | Parcial | El prompt distingue estado previo y pide evidencia, pero no se probó con un agente real |
| CA-24 | Verificado | Matriz de selección y preparación Docker real |
| CA-25 | Verificado | Fallback a global `configured`; escaneo global real |
| CA-26 | Verificado | `TestResolveMatrix`: Docker remoto/caído no cambia una elección explícita |
| CA-27 | Verificado | Segunda ejecución reutiliza imagen, binario y volumen |
| CA-28 | Verificado | Offline sin base devuelve 3; con base válida completa |
| CA-29 | Verificado | Checksum inválido, tar con `..`, enlace y binario con versión errónea |
| CA-30 | Verificado | `TestEnsureTrivyConcurrentInstallsOnce` con bloqueo |
| CA-31 | Verificado | Setup no usa sudo, no toca el proyecto y escribe progreso en stderr |
| CA-32 | Verificado | `--no-auto-install` no descarga y falla con 3 |
| CA-33 | Parcial | Preguntas interactivas probadas con entrada simulada, no en TTY real |
| CA-34 | Verificado | Setup global crea el enlace y el bloque de PATH; segunda ejecución no duplica |
| CA-35 | Verificado | Setup no interactivo real, sin esperar entrada |
| CA-36 | Verificado | Preferencia guardada que falla devuelve error sin fallback |
| CA-37 | Verificado | Setup repetido es idempotente; cancelar no escribe configuración |
| CA-38 | Verificado | Volumen y base sobreviven a contenedores; segundo proyecto lo reutiliza |
| CA-39 | Parcial | Protocolo exclusivo→compartido probado con bloqueos; falta prueba de escaneo concurrente completo |
| CA-40 | Verificado | Fallo de actualización no declara base vigente |
| CA-41 | Verificado | Actualizador con red y volumen, sin proyecto; args y ejecución real |
| CA-42 | Parcial | Se leen archivos de disco, pero no hay prueba específica de cambios sin commit |
| CA-43 | Verificado | Fixtures sin Git escaneados correctamente |
| CA-44 | Parcial | `scan` sin ruta usa el directorio actual por construcción; no hay prueba de ruta explícita con Docker |
| CA-45 | Verificado | Dos ejecuciones idénticas salvo `run` y duraciones |
| CA-46 | Verificado | `--exclude` real: `partial=true`, `not_analyzed`, origen `cli` |
| CA-47 | Verificado | Semgrep desactivado: `disabled`, sin descarga, sin código 3 |
| CA-48 | Verificado | Semgrep habilitado: reglas locales, métricas/versión off, 3 reglas |
| CA-49 | Verificado | `scan` no expone `--semgrep`; sin configuración queda desactivado |
| CA-50 | Verificado | `enforced` con adaptadores falla antes de analizar y con código 3 |
| CA-51 | Parcial | `--version` y `NO_COLOR` probados; falta prueba de `--log-format json` como contrato |
| CA-52 | Verificado | Claves prohibidas ignoradas con error de política; controles intactos |
| CA-53 | Verificado | Exclusiones/excepciones visibles; excepción sin `expires` rechazada |
| CA-54 | Pendiente | Firma, SBOM y checksums configurados; falta un release real que verificar |
| CA-55 | Verificado | Reportes y salidas 0600; directorios 0700; `--report-out` privado |
| CA-56 | Verificado | CVSS de Trivy, alcanzabilidad de govulncheck; campos ausentes nulos; orden estable |
| CA-57 | Verificado | `recipes` detecta candidatos y solo publica recetas confirmadas; prompt bloquea el resto |
| CA-58 | Verificado | Severidad máxima entre fuentes y `severity_others`; `info` no bloquea; `unknown` según política |

## Pendientes para cerrar H7-04

1. CA-54: ejecutar un release real y verificar firma, SBOM y checksums.
2. CA-23 y CA-33: prueba con agente consumidor real y TTY interactivo.
3. CA-39, CA-42, CA-44, CA-51: ampliar pruebas de concurrencia, Git y contrato de logs.
