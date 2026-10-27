# Spikes del Hito P — resultados verificados

> **Fecha:** 27 de octubre de 2026 · **Plataforma de ejecución:** macOS 27 (Darwin/arm64), Docker 29.9.2, Go 1.26.4, PHP 8.5.7, Node 24.14.1, Python 3.14.3.
> Cada resultado se obtuvo ejecutando las herramientas reales; los comandos y salidas relevantes quedan transcritos para que sean reproducibles.

---

## P-07 — Trivy: flags reales (T-01)

**Versión candidata fijada:** Trivy **v0.76.1** (último release al 27-10-2026).

**Descarga y verificación.** El artefacto se llama `trivy_0.76.1_macOS-ARM64.tar.gz` (no `darwin-arm64`; la nomenclatura del manifiesto debe usar la del proyecto). SHA-256 calculado y comparado con `trivy_0.76.1_checksums.txt`: **coincide**.

**Flags confirmados contra `trivy fs --help`:**

| Necesidad | Flag confirmado |
| --- | --- |
| Escaneo de directorio | `fs` |
| Salida | `--format json` |
| Escáneres | `--scanners vuln,secret,misconfig` |
| Sin actualizar base | `--skip-db-update` |
| Sin actualizar base Java | `--skip-java-db-update` |
| Sin consultas de identificadores | `--offline-scan` |
| Sin actualizar checks | `--skip-check-update` |
| **Sin comprobación de versión** | **`--skip-version-check`** |
| Telemetría | `--disable-telemetry` |
| Caché | `--cache-dir` |
| Exclusiones | `--skip-dirs`, `--skip-files` |
| Actualización separada | `--download-db-only`, `--download-java-db-only` |
| Repositorios | `--db-repository`, `--java-db-repository`, `--checks-bundle-repository` |
| Salida limpia | `--no-progress`, `--quiet` |
| Timeout | `--timeout` |

**Salida real.** Sobre un fixture Go con `golang.org/x/text v0.3.0`, un `.env` y un `Dockerfile`:

```text
app/go.mod   lang-pkgs  5 vulnerabilidades
Dockerfile   config     2 misconfiguraciones
secrets.txt  secret     1 secreto (github-pat, CRITICAL)
```

**Hallazgos del spike:**

1. **La base de vulnerabilidades pesa 1,6 GB** (`cache/db/trivy.db`, 1 639 309 312 bytes) y se descarga como artefacto OCI (`mirror.gcr.io/aquasec/trivy-db:2`). Consecuencias: el volumen Docker debe dimensionarse para ≥ 2 GB, el timeout de actualización no puede ser de segundos y el tope de salida del motor aplica solo a stdout, nunca a la base.
2. `metadata.json` de la base **no aparece en el JSON del reporte** (`Metadata` vacío). La CLI debe leer `cache/db/metadata.json` directamente para registrar `UpdatedAt`/`DownloadedAt` (CA-39).
3. `--skip-check-update` sin caché de checks **no falla**: Trivy cae a los checks embebidos y escribe un `ERROR` en stderr. El adaptador debe tolerar ese caso y registrar diagnóstico, no marcar la ejecución incompleta por ello.
4. Los secretos de ejemplo de AWS (`AKIA…EXAMPLE`) están en la allowlist de Trivy: un corpus de fixtures debe usar valores aleatorios, nunca los de documentación.
5. Trivy **no incluye los archivos ocultos en `Results` si no coinciden**, pero sí escanea `.env` cuando se le pasa la ruta o el directorio (verificado con `--debug`). El adaptador no debe excluir dotfiles por su cuenta.
6. `--scanners misconfig` descarga el bundle de checks a `<cache>/policy/content`; ese directorio forma parte de la fuente `trivy-checks`.

**Decisión derivada.** El manifiesto usa la nomenclatura del proyecto (`macOS-ARM64`, `Linux-ARM64`, `Linux-64bit`, `macOS-64bit`). Los argumentos de `trivyArgs` se fijan con esta versión y cualquier cambio exige repetir este spike (regla 5 del workload).

---

## P-08 — Docker: propiedad del volumen (T-02, O-3)

**Prueba real** con volumen nombrado y Alpine 3.20:

```text
volumen vacío creado por el daemon:
  root   escribe /cache/x/rootfile            → OK, uid 0
  uid 1000 escribe /cache/x/userfile          → Permission denied
  root   vuelve a leer                        → los archivos siguen siendo uid 0
```

**Imagen de Trivy:** `Config.User` vacío (root). El entrypoint es `trivy`.

**Decisión (cierra O-3).** El contenedor se ejecuta **como root dentro del contenedor** (comportamiento por defecto de la imagen), sin `--user`. La caché del volumen queda propiedad de `root` y es consistente entre el contenedor actualizador y el escáner. Pasar `--user $(id -u)` haría fallar la escritura en un volumen creado por el daemon y obligaría a un `chown` previo, que no está disponible sin elevar privilegios. Mitigaciones que se mantienen: volumen con nombre propio del usuario (`cgc-scan-trivy-cache-<uid>`), solo bases y metadatos dentro (nunca código), y `--read-only`, `--cap-drop ALL`, `--network none` en el escáner. Se documenta que pertenecer al grupo `docker` equivale a root en el host; por eso el aislamiento de red y el nombre del volumen son las garantías relevantes.

**Digest fijado:** `ghcr.io/aquasecurity/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c` (índice multiarquitectura de v0.76.1).

**Plantilla validada** (escaneo completo, código 0, 24 134 bytes de JSON):

```bash
docker run --rm --network none --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 512 --memory 2g \
  -v "$PROYECTO":/src:ro -v "$VOLUMEN":/cache \
  "$IMAGEN@sha256:..." fs --cache-dir /cache --format json \
  --scanners vuln,secret,misconfig --skip-db-update --skip-java-db-update \
  --offline-scan --skip-check-update --skip-version-check \
  --disable-telemetry --no-progress /src
```

La combinación `--read-only --tmpfs /tmp` funciona con Trivy 0.76.1: necesita `/tmp` escribible para temporales, no para la base.

---

## P-09 — Aislamiento `configured` con `strace` (R1, CA-03)

**Método.** Se descargó el binario **Linux-ARM64** de la misma versión (checksum verificado) y se ejecutó dentro de `debian:bookworm-slim` con red habilitada, `strace -f -e trace=connect`, HOME aislado, base y proyecto montados en solo lectura. La prueba busca conexiones a destinos no locales.

**Hallazgo crítico.** Con las opciones que el design contemplaba (`--skip-db-update --skip-java-db-update --offline-scan --skip-check-update --disable-telemetry`), Trivy **sí abre conexiones externas**:

```text
connect(9, {AF_INET, htons(53), 192.168.65.7})   ← DNS del contenedor
connect(8, {AF_INET, htons(53), 104.26.2.26})    ← DNS check.trivy.dev
connect(8, {AF_INET, htons(443), 104.26.2.26})   ← HTTPS check.trivy.dev
```

El destino es `check.trivy.dev`: la **comprobación de versión**. `--disable-telemetry` no la desactiva.

**Corrección verificada.** Añadiendo **`--skip-version-check`** la ejecución produce **cero llamadas a `connect`** (0 líneas en el trace) y el escaneo termina con código 0 y 24 134 bytes de JSON, idénticos a la ejecución online.

**Consecuencias:**

1. `trivyArgs` incluye `--skip-version-check` en todas las invocaciones de escaneo. Sin él, el nivel `configured` sería falso y CA-03 fallaría.
2. La prueba de aislamiento de H6-05 debe ejecutarse por versión y **fallar ante cualquier `connect` no local**, tal como está escrita; no basta con revisar la lista de flags.
3. El proxy inválido (`HTTPS_PROXY=http://127.0.0.1:9`) sigue siendo defensa en profundidad, no la garantía: un motor que ignore `*_PROXY` no se ve afectado.
4. Se documenta en el registro de decisiones técnicas (T-01/R1) porque cambia el diseño.

---

## P-10 — govulncheck: base local y uso como biblioteca (O-2)

**Versión fijada:** `govulncheck v1.9.0` (módulo `golang.org/x/vuln v1.9.0`).

**Base local verificada.** La base de Go es un árbol estático:

```text
index/modules.json   1 443 módulos
index/vulns.json     4 712 avisos
ID/<GO-…>.json       4 712 archivos (20 MB en total)
```

Se descargó el espejo completo y `govulncheck -db file://… -mode=source -format=json ./...` terminó con código 0 **sin red** y produjo 38 hallazgos (incluidos `GO-2021-0113`, `GO-2022-1059`, `GO-2026-5970` y avisos del stdlib del toolchain 1.26.4). Tiempo de espejado: ~1 min 44 s con 16 descargas en paralelo.

**Formato de salida.** Es un **flujo de objetos JSON concatenados** (`config`, `SBOM`, `progress`, `osv`, `finding`), no un único documento. El parser debe usar `json.Decoder` en bucle y tolerar truncamiento.

**Uso como biblioteca — sí.** `golang.org/x/vuln/scan` expone:

```go
cmd := scan.Command(ctx, "-db", "file://…", "-mode=source", "-format=json", "./...")
cmd.Env = env
cmd.Stdout = &buf
cmd.Stderr = &errBuf
err := cmd.Start(); // + cmd.Wait()
```

**Decisión (cierra O-2).** Se enlaza como biblioteca. Ventajas: no se distribuye ni actualiza un binario adicional, y se reutiliza el parser de objetos JSON del propio proyecto. Limitación asumida: sigue requiriendo el toolchain Go del usuario en modo fuente; si falta, el adaptador se omite con `requirement_missing` (CA-06).

**Nota de reproducibilidad.** Los avisos del stdlib dependen de la versión de Go del usuario. El reporte registra `go_version`, `scanner_version` y el estado de la base (RF-12), y el fingerprint no incluye esa versión.

---

## P-11 — Adaptadores: ESLint, Psalm, cargo-audit y Bandit

Versiones fijadas verificadas contra los registros el 27-10-2026:

| Herramienta | Versión | Licencia | Distribución |
| --- | --- | --- | --- |
| ESLint | 10.13.0 | MIT | npm |
| eslint-plugin-security | 4.2.0 | Apache-2.0 | npm |
| @typescript-eslint/parser | 8.72.1 | MIT | npm |
| typescript | 5.9.3 | Apache-2.0 | npm |
| Psalm | 6.20.3 | MIT | phar (SHA-256 `bda19a8c…ecc828`) |
| cargo-audit | 0.22.2 | MIT OR Apache-2.0 | binario del release (SHA-256 `ec7ca426…175af`) |
| Bandit | 1.9.4 | Apache-2.0 | wheel de PyPI |

### ESLint (JS y TSX)

Invocación validada (sin configuración del proyecto):

```bash
eslint --no-config-lookup --config <config-generada>.mjs --format json <rutas>
```

- `--no-config-lookup` impide que ESLint cargue `eslint.config.*` del repositorio (mitigación T-05).
- Salida: arreglo JSON; cada mensaje trae `ruleId`, `severity` (1=warn, 2=error), `line`, `column`, `message`, `endLine`, `endColumn`.
- JS detectado: `detect-eval-with-expression`, `detect-child-process`, `detect-non-literal-regexp`, `detect-non-literal-require`.
- TSX detectado: `detect-eval-with-expression` en un `.tsx` con parser TypeScript y JSX habilitado. **Un plugin que declare tipos no demuestra cobertura de TSX; la prueba se hace sobre el fixture TSX real** (PRD §5).
- Nota: ESLint devuelve 1 cuando hay errores de lint; en el adaptador eso **no** es un fallo de ejecución, es una ejecución completa con hallazgos.

### Psalm (PHP, taint)

Invocación validada:

```bash
php psalm.phar --config=<psalm.xml generado> --no-cache --taint-analysis \
  --output-format=json --no-progress
```

- Salida: arreglo de objetos con `type` (`TaintedHtml`, `TaintedShell`, …), `severity`, `file_name`, `line_from`, `message`, `snippet` y `taint_trace` (origen → sumidero).
- Código de salida 2 = problemas encontrados; no es un fallo del adaptador.
- El `psalm.xml` debe generarse con `resolveFromConfigFile="true"` y un `<projectFiles>` acotado a las rutas seleccionadas, para que las exclusiones del plan lleguen al motor (T-08).
- Psalm requiere PHP ≥ 8.2 y `composer`/dependencias del proyecto para autoload completo; si faltan, se omite con `requirement_missing` (CA-06).

### cargo-audit (Rust)

Invocación validada con base local:

```bash
cargo-audit audit --db <advisory-db> --no-fetch --stale --json -f Cargo.lock
```

- `--no-fetch` y `--stale` impiden cualquier acceso git/red durante el escaneo.
- Salida JSON con `database.advisory-count`, `lockfile.dependency-count` y `vulnerabilities.list[]` con `advisory` (id, package, title, description, severity si existe), `versions.patched` y `package`.
- Código de salida 1 = vulnerabilidades encontradas.
- La base RustSec se obtiene en la **preparación** (clonado o espejo), nunca durante el escaneo; pesa 6,8 MB con `--depth 1`.

### Bandit (Python)

Invocación validada:

```bash
bandit -r <rutas> -f json -q
```

- Salida: `results[]` con `test_id`, `issue_severity` (HIGH/MEDIUM/LOW), `issue_confidence` (HIGH/MEDIUM/LOW), `filename`, `line_number`, `issue_text`, `code`, `more_info`, y `metrics`.
- Detectados: B602 (`shell=True`), B307 (`eval`), B105 (contraseña embebida), B324 (MD5), B404 (import de subprocess).
- **`issue_text` incluye el valor del secreto** (p. ej. `'hunter2-super-secret'`): `Redact` debe enmascararlo antes de persistir la salida (CA-13).
- El código de salida 1 indica hallazgos, no fallo.

### Requisitos de toolchain confirmados

| Adaptador | Faltante → estado | Consecuencia |
| --- | --- | --- |
| Go (govulncheck) | sin toolchain Go o sin módulos | `requirement_missing` → ejecución incompleta |
| JS/TS (ESLint) | sin Node o sin el árbol npm fijado | `requirement_missing` |
| PHP (Psalm) | sin PHP/Composer/autoload | `requirement_missing` |
| Rust (cargo-audit) | sin base RustSec local | `requirement_missing` |
| Python (Bandit) | sin intérprete Python compatible | `requirement_missing` |

Ningún caso produce un resultado limpio (CA-06).
