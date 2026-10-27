# CGC Scan — Design Doc v1.0

> **Versión:** 1.1 (borrador para revisión) · **Fecha:** 27 de octubre de 2026
> **Complementa:** `requisitos-cli-seguridad.md` v0.10 (en adelante, **PRD**; se cita como "PRD §x")
> **Stack:** Go (binario estático, `CGO_ENABLED=0`) · Trivy (Docker o binario global) · adaptadores por lenguaje · Semgrep CE opcional
> **Convención de estados:** *Confirmado* = decisión del PRD o del usuario. *Propuesto* = decisión de este diseño, revisable.

Este documento responde a "¿cómo lo construimos?". El qué, el para quién, los requisitos (RF), los criterios de aceptación (CA), los riesgos de producto y el contrato público de la CLI y del reporte viven en el PRD y **no se repiten aquí**; cuando un tema ya está definido allí, se referencia.

---

## 1. Arquitectura del sistema

### 1.1 Vista general

```text
┌──────────────────────── cgc-scan (un binario Go, CGO=0) ─────────────────────────┐
│  cli (cobra) → config.Resolve → orchestrator                                      │
│                                     │                                             │
│      ┌────────────┬────────────┬────┴───────┬─────────────┬──────────────┐        │
│  provision     discovery     runner      normalize      policy        report      │
│  (manifiesto,  (unidades,    (docker |   (modelo,       (umbral,      (json |     │
│   bases,       exclusiones)  global)     fingerprint,   excepciones,  texto |     │
│   locks)                                 correlación)   exit code)    prompt)     │
└─────────────────────────────────────┬─────────────────────────────────────────────┘
                                      ▼
     Trivy · govulncheck · ESLint · Psalm · cargo-audit · Bandit · [Semgrep opcional]
     (procesos hijos con entorno mínimo, HOME aislado y proyecto en solo lectura)
```

Principios de diseño derivados del PRD §1:

- **El orquestador es el único que decide.** Los motores son procesos externos tratados como no confiables: su salida se valida, se limita en tamaño y se normaliza antes de usarse.
- **Preparación y escaneo son fases separadas** (PRD §6.6). Ningún código de la fase de preparación abre el directorio del proyecto, y ningún código de la fase de escaneo tiene acceso a red del lado de la CLI.
- **Sin estado oculto.** Todo lo que la CLI instala o modifica queda registrado en `state.json` (sección 4).
- **Dependencias mínimas.** Se prefiere la biblioteca estándar; cada dependencia directa se justifica en la sección 2.

### 1.2 Flujo de `scan`

| Paso | Fase | Qué ocurre | Paquete |
| --- | --- | --- | --- |
| 1 | Entrada | Parsear flags, cargar configuración de usuario y política del proyecto, resolver precedencia (PRD §6.8). Error aquí → código 2 | `cli`, `config` |
| 2 | Preparación | Resolver runner según la matriz de PRD §6.2 | `runner`, `provision` |
| 3 | Preparación | Tomar el bloqueo exclusivo de caché, provisionar motor y actualizar bases (omitido con `--offline`), pasar a bloqueo compartido y leer los metadatos de la base | `provision` |
| 4 | Preparación | Verificar aislamiento exigido (`--require-isolation`) y requisitos globales de los adaptadores; los que dependen del proyecto se comprueban tras el descubrimiento | `runner`, `adapter` |
| 5 | Escaneo | Descubrir unidades de proyecto y construir el plan de cobertura (sin ejecutar nada) | `discovery`, `plan` |
| 6 | Escaneo | Ejecutar invocaciones con concurrencia, timeouts y cancelación | `orchestrator` |
| 7 | Posproceso | Parsear, redactar, normalizar y correlacionar hallazgos | `adapter`, `normalize` |
| 8 | Posproceso | Aplicar política y excepciones; decidir el código de salida | `policy` |
| 9 | Salida | Renderizar JSON, texto o prompt; escribir `--report-out` de forma atómica | `report` |

### 1.3 Flujo de `setup`

| Paso | Qué ocurre |
| --- | --- |
| 1 | Detectar si Docker local responde (contexto local, daemon accesible, arquitectura soportada) |
| 2 | Obtener la elección Docker/global y la de Semgrep (pregunta interactiva o flags `--trivy-mode` y `--semgrep`) |
| 3 | Si es `global`: provisionar Trivy (sección 7), crear el enlace en el directorio de ejecutables del usuario y, solo aquí, editar el perfil de shell |
| 4 | Si es `docker`: descargar la imagen fijada por digest y crear el volumen de caché |
| 5 | Escribir `config.toml` y `state.json` de forma atómica; cancelar a mitad no deja estado a medias (CA-37) |

---

## 2. Stack técnico y decisiones

| Capa | Tecnología | Alternativas descartadas | Razón | Costo/mes |
| --- | --- | --- | --- | --- |
| Lenguaje | Go, `CGO_ENABLED=0`, versión estable más reciente fijada en `go.mod` con directiva `toolchain` | Rust, Node/TypeScript | Binario único y estático, compilación cruzada amd64/arm64 trivial, buen manejo de procesos y concurrencia, ecosistema de seguridad (Trivy, govulncheck) en Go. Se requiere Go ≥ 1.24 por `os.Root` | 0 |
| CLI | `spf13/cobra` | `urfave/cli`, parser propio | Subcomandos, ayuda y completado de shell (RF-32) sin código propio | 0 |
| Configuración | TOML con `pelletier/go-toml/v2` | YAML | Sin tipado implícito ni anclas; adecuado para archivos que provienen de repositorios no confiables (ADR-04) | 0 |
| Procesos | `os/exec` de la biblioteca estándar | Bibliotecas de terceros | Control total de entorno, grupos de procesos y cancelación | 0 |
| Docker | Invocar el binario `docker` sin shell | SDK de Docker (`docker/docker`) | Árbol de dependencias mucho menor; el contexto remoto se detecta con el propio CLI (ADR-02) | 0 |
| Concurrencia | `golang.org/x/sync/errgroup` | Pool propio | `SetLimit` y propagación de cancelación | 0 |
| Bloqueos | `gofrs/flock` | `syscall.Flock` directo | Interfaz portable macOS/Linux, mantenida | 0 |
| Coincidencia de patrones | `github.com/bmatcuk/doublestar/v4` | `path.Match`, implementación propia | Las exclusiones del proyecto usan `**` (sección 9.4), que `path.Match` no soporta | 0 |
| Registro | `log/slog` | zap, zerolog | Estándar; handler a stderr, texto o JSON | 0 |
| Esquema de reporte | JSON Schema escrito a mano, embebido con `go:embed`; validación en pruebas con `santhosh-tekuri/jsonschema` | Generarlo desde structs | El esquema es un contrato público y debe revisarse como tal (ADR-06) | 0 |
| Pruebas | `testing`, `go-cmp`, `rogpeppe/go-internal/testscript`, fuzzing nativo | Frameworks de aserciones | Pruebas de CLI de extremo a extremo con archivos de referencia | 0 |
| Build y release | GoReleaser, `cosign` (firma sin clave), SBOM CycloneDX, atestación de procedencia SLSA | Scripts propios | Cumple PRD §6.7 | CI |

**Política de dependencias (Propuesto).** Sin plugins dinámicos: todos los adaptadores se compilan dentro del binario. Cada dependencia directa nueva requiere una línea en este documento. `go mod verify` y `govulncheck` sobre la propia CLI corren en CI. `GOFLAGS=-mod=readonly` en los builds.

---

## 3. Estructura del repositorio

```text
cgc-scan/
├── cmd/cgc-scan/main.go          # señales, slog, os.Exit(code)
├── internal/
│   ├── cli/                      # comandos: setup, doctor, scan, compare, update-db, recipes
│   ├── config/                   # config de usuario, política del proyecto, precedencia
│   ├── recipes/                  # candidatos detectados, confirmación, recetas de confianza
│   ├── platform/                 # rutas, perfil de shell, grupos de procesos, flock
│   ├── manifest/                 # carga del manifiesto de confianza (el dato vive en manifest/trust.json)
│   ├── provision/                # instalación verificada de motores y bases
│   ├── runner/                   # docker, global; niveles de aislamiento
│   ├── discovery/                # unidades de proyecto, exclusiones, os.Root
│   ├── plan/                     # plan de cobertura
│   ├── adapter/                  # trivy, govulncheck, eslint, psalm, cargoaudit, bandit, semgrep
│   ├── orchestrator/             # concurrencia, timeouts, cancelación
│   ├── normalize/                # modelo, fingerprint, correlación, severidad
│   ├── masking/                  # enmascarado de secretos y saneado de texto
│   ├── policy/                   # umbral, excepciones, decisión del código de salida
│   ├── report/                   # render JSON, texto y prompt; esquema
│   └── compare/                  # nuevo, persistente, resuelto, no evaluado
├── schemas/report.schema.json    # contrato público (embebido)
├── templates/prompt/*.tmpl       # plantilla versionada del formato prompt
├── manifest/trust.json           # versiones, digests y checksums de motores
├── testdata/fixtures/            # proyectos vulnerables/corregidos por lenguaje
└── tools/update-manifest/        # utilidad de CI que verifica firmas y regenera el manifiesto
```

Todo el código vive bajo `internal/`: el contrato público es la CLI y el JSON, no una API Go (PRD §8, §9).

---

## 4. Estado local y archivos

### 4.1 Ubicaciones

La resolución vive en `internal/platform/paths.go`. En Linux se respetan las variables XDG; en macOS se usan `os.UserConfigDir()` y `os.UserCacheDir()`. Se puede sobrescribir con `CGC_SCAN_CONFIG_DIR`, `CGC_SCAN_DATA_DIR` y `CGC_SCAN_CACHE_DIR`.

| Contenido | Ubicación lógica | Permisos |
| --- | --- | --- |
| `config.toml` (editable por el usuario) | `<config>/cgc-scan/` | 0600 |
| `state.json` (escrito solo por la CLI) | `<data>/cgc-scan/` | 0600 |
| Motores instalados | `<data>/cgc-scan/engines/<motor>/<versión>/` | 0700 (dirs), 0755 (binario) |
| Caché de bases (modalidad global) | `<cache>/cgc-scan/trivy/` | 0700 |
| Salidas originales de motores | `<cache>/cgc-scan/runs/<run-id>/` | 0700 |
| Bloqueos | `<data>/cgc-scan/locks/` | 0700 (directorio) y 0600 (cada archivo de bloqueo) |
| HOME aislado de los motores | `<data>/cgc-scan/sandbox-home/<motor>/` | 0700 |
| Enlace global a Trivy | `~/.local/bin/trivy` → motor instalado | enlace simbólico |

El enlace global solo se crea si no existe un `trivy` ajeno en esa ruta (PRD §6.3). La CLI invoca siempre la **ruta absoluta** del motor instalado, nunca `PATH`.

### 4.2 `config.toml`

```toml
trivy_mode = "docker"          # docker | global
semgrep_enabled = false        # solo cambia con `setup`

[cache]
dir = ""                       # vacío = valor por defecto de la plataforma

[db]
warn_after = "72h"             # Propuesto
block_after_offline = "168h"   # Propuesto

[[recipes]]
project = "/ruta/absoluta/al/proyecto"   # las recetas se guardan por proyecto
unit = "svc/api"

[recipes.test]
command = "npm test"
workdir = "svc/api"

[recipes.build]
command = "npm run build"
workdir = "svc/api"
```

Las recetas viven en la configuración de usuario, nunca en el archivo del proyecto (sección 9.5). La clave `project` es la raíz absoluta del proyecto, de modo que un mismo usuario puede confirmar recetas para varios proyectos sin que se mezclen.

### 4.3 `state.json`

| Campo | Tipo | Descripción |
| --- | --- | --- |
| `schema` | int | Versión del formato de estado |
| `trivy_mode_origin` | string | `setup`, `flag`, `default` |
| `installs[]` | objeto | `engine`, `version`, `path`, `sha256`, `installed_at` |
| `profile_edits[]` | objeto | `file`, `marker`, `backup_path`, `applied_at` (CA-37) |
| `docker_volume` | string | Nombre del volumen de caché creado por la CLI, con sufijo de usuario (`cgc-scan-trivy-cache-<uid>`) |

La escritura es atómica: archivo temporal en el mismo directorio, `fsync` y `os.Rename`.

### 4.4 Política del proyecto (`cgc-scan.toml`, Propuesto)

Se lee con la tabla de reglas de PRD §6.8: es dato no confiable. Se decodifica primero a un mapa, se separan las claves permitidas de las prohibidas y las prohibidas se descartan registrando un error de política (CA-52). Nunca se usa decodificación que falle ante claves desconocidas, porque eso permitiría a un repositorio hostil romper el escaneo.

```toml
fail_on = "high"                       # solo puede endurecer el umbral

exclude = ["docs/examples/**"]         # visible en coverage.exclusions

[[exception]]
fingerprint = "3fa19c0e5b7d4a21c8d6e0f19a2b4c77"
reason = "No alcanzable: la función afectada no se invoca"
owner = "equipo-seguridad"
expires = 2027-01-31                   # obligatoria (CA-53)
```

Cada exclusión —venga de donde venga— se registra en `coverage.exclusions` con su `origin` (`intrinsic`, `user`, `policy`, `cli`). El origen no es decorativo: decide si el escaneo se marca como parcial (sección 9.4), porque solo las exclusiones **elegidas** lo hacen.

La `exclude` de este archivo se aplica en el nivel *policy* de la matriz de precedencia (sección 9.4): solo puede agregar sobre las exclusiones intrínsecas y es reemplazada por `--exclude` de la línea de comandos. Un repositorio hostil puede reducir la cobertura, pero la reducción queda visible en el reporte y nunca puede silenciar un hallazgo por encima del umbral.

---

## 5. Núcleo: interfaces y contratos internos

### 5.1 Runner

```go
// internal/runner/runner.go
type IsolationLevel string

const (
	IsolationEnforced   IsolationLevel = "enforced"
	IsolationConfigured IsolationLevel = "configured"
)

type Runner interface {
	Kind() string // "docker" | "global"
	// Isolation declara el nivel que este runner puede garantizar en este equipo.
	Isolation(ctx context.Context) (IsolationLevel, error)
	Run(ctx context.Context, inv Invocation) (Result, error)
}

type Invocation struct {
	Engine    string            // "trivy", "govulncheck", ...
	Args      []string          // nunca pasan por shell ni incluyen datos del proyecto sin validar
	ProjectRO string            // ruta absoluta, solo lectura
	Env       map[string]string // se suma a la lista permitida base; las claves admitidas están acotadas a una lista explícita
	Timeout   time.Duration
	MaxOutput int64             // tope de bytes de stdout
}
```

### 5.2 Adaptador

```go
// internal/adapter/adapter.go
type Adapter interface {
	ID() string
	Applies(u discovery.Unit) bool
	Requirements() []Requirement // toolchain, bases, reglas
	Invocations(u discovery.Unit, p plan.Plan) ([]runner.Invocation, error) // p lleva el conjunto efectivo de exclusiones (sección 9.4)
	Parse(raw []byte) (Parsed, error) // tolerante a salida truncada o parcial
	Redact(raw []byte) []byte         // se aplica antes de persistir la salida original
}

type Parsed struct {
	Findings    []normalize.Finding
	Diagnostics []Diagnostic // errores de parsing del propio motor, limitaciones
}
```

### 5.3 Modelo de hallazgo

```go
// internal/normalize/finding.go
type Finding struct {
	Fingerprint string
	Kind        Kind // vulnerability | secret | misconfig | code
	Title       string
	Severity    Severity // original por fuente + normalizada
	Confidence  *Confidence // confianza de la fuente si la entrega (Bandit, Semgrep); nunca inventada
	IDs         []Identifier // CVE, GHSA, CWE, RUSTSEC, GO-...
	Package     *PackageRef  // ecosistema, nombre, versión, versión corregida
	Locations   []Location   // rutas relativas
	Evidence    Evidence     // ya enmascarada
	Sources     []SourceRef  // motor, versión, regla
	Remediation []Remediation
	Priority    *Priority // CVSS, EPSS, KEV: punteros nulos si la fuente no los provee
}
```

Regla de oro (PRD §9): un campo que el motor no entrega es `nil`, nunca un valor inventado.

### 5.4 Decisión del código de salida

Función pura y probada con tabla, sin efectos secundarios (PRD §8.1):

```go
func Decide(r RunOutcome, p PolicyOutcome) int {
	switch {
	case r.Canceled:
		return 130
	case r.InvalidArgs:
		return 2
	case !r.Complete: // incluye fallos de preparación y aislamiento no cumplido
		return 3
	case p.Violated:
		return 1
	default:
		return 0
	}
}
```

En v1 la incompletitud prevalece sobre el incumplimiento de política (3 antes que 1), que es el criterio recomendado en PRD §15. La alternativa para CI —bloquear por hallazgos confirmados aunque falte cobertura, con dos indicadores o un código adicional— sigue siendo decisión abierta.

---

## 6. Runners y aislamiento

El objetivo, los niveles y la política están en PRD §6.6. Aquí se define cómo se implementan.

### 6.1 Runner Docker (`enforced`)

Plantilla de invocación del escáner. Los flags de Trivy se encapsulan en un constructor (`trivyArgs`) con pruebas de referencia y **se validan contra la versión fijada en el manifiesto** antes de cada actualización de motor.

```bash
docker run --rm \
  --network none \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory 2g \
  -v "$PROYECTO":/src:ro \
  -v "$VOLUMEN_CACHE":/cache \
  "$IMAGEN_TRIVY@sha256:..." \
  fs --format json --scanners vuln,secret,misconfig \
     --skip-db-update --skip-java-db-update --offline-scan \
     --skip-check-update --skip-version-check --disable-telemetry \
     --cache-dir /cache /src
```

Decisiones de diseño:

- **La salida va por stdout del contenedor** y la CLI la captura con tope de bytes (`MaxOutput`). No se monta ningún directorio de salida, lo que reduce la superficie.
- **El contenedor corre como root dentro del contenedor** (usuario por defecto de la imagen oficial), sin `--user`. Probado en P-08: un volumen creado por el daemon no permite escribir a un uid distinto de 0 sin un `chown` previo, y el `chown` exigiría privilegios que `scan` no pide. La caché contiene solo bases y metadatos, y el nombre del volumen es propio del usuario.
- **El volumen de vulnerabilidades pesa ~1,6 GB** (P-07). La preparación dimensiona el timeout de descarga y nunca aplica el tope de stdout a la base.
- **Contenedor actualizador separado**: con red y el volumen de caché en lectura/escritura, sin el proyecto montado (PRD §6.4). Usa `--download-db-only` y `--download-java-db-only`.
- Se ejecuta `docker context inspect` antes de usar Docker: un contexto remoto no es elegible (PRD §6.3). La CLI nunca cambia el contexto global.
- **El volumen de caché lleva el identificador de usuario en el nombre:** `cgc-scan-trivy-cache-<uid>`, y su nombre exacto se registra en `state.json`. Dos personas que comparten un daemon no comparten volumen, que es lo que hace efectiva la mitigación de envenenamiento de caché de la sección 13. Pertenecer al grupo `docker` equivale a root en el host; la mitigación real es el aislamiento de red y no compartir volumen.

### 6.2 Runner global (`configured`)

El binario se invoca por ruta absoluta con cinco capas, ninguna de las cuales sustituye a las demás:

1. **Opciones offline del motor** (equivalentes a las de la plantilla anterior). Para Trivy incluyen `--offline-scan`, `--skip-db-update`, `--skip-java-db-update`, `--skip-check-update`, **`--skip-version-check`** y `--disable-telemetry`. El spike P-09 demostró que sin `--skip-version-check` Trivy contacta `check.trivy.dev` aun con el resto de las opciones; la opción es obligatoria.
2. **Entorno mínimo por lista permitida**, no por lista de exclusión: `PATH` acotado, `LANG`, `TMPDIR`, y `HOME` apuntando al directorio aislado **de ese motor**, para que un motor no pueda alterar el entorno de otro. Así un motor no lee `~/.npmrc`, `~/.aws`, ni configuraciones de otras herramientas con credenciales, ni hereda variables como `*_TOKEN`.
3. **Variables de proxy hacia un destino inválido** (por ejemplo `HTTPS_PROXY=http://127.0.0.1:9`) como defensa adicional: los motores que respetan el proxy fallan en lugar de conectarse. El puerto debe estar **cerrado**; el criterio de la sección 15.2 admite conexiones a bucle local, así que un servicio escuchando en ese puerto invalidaría la prueba. No es una garantía; no cubre motores que lo ignoran.
4. **Telemetría y comprobaciones de versión desactivadas** con las opciones y variables propias de cada motor.
5. **Verificación en CI por cada versión fijada** (sección 15.2): el escaneo se ejecuta bajo `strace -f -e trace=connect` y la prueba falla ante cualquier `connect` a una dirección no local.

Si una versión de motor no admite desactivar una función de red, el adaptador lo declara en `Requirements()` y queda omitido con causa explícita (PRD §6.6).

### 6.3 Extensión opcional: `enforced` en Linux sin Docker (Propuesto, fuera de v1)

Con `syscall.SysProcAttr{Cloneflags: CLONE_NEWUSER | CLONE_NEWNET}` Go puede lanzar el motor en un espacio de red vacío sin privilegios, cuando el kernel permite espacios de usuario sin privilegios. Ojo: Go no escribe `/proc/<pid>/uid_map`, así que el proceso hijo queda como `nobody` (65534) salvo que el padre establezca el mapeo a mano; el sondeo de la sección 6.3 debe comprobar el uid real, no solo la interfaz de loopback. Varias distribuciones lo restringen, por lo que se **sondea en tiempo de ejecución** (se lanza un proceso trivial y se verifica que solo exista la interfaz de loopback). Si el sondeo pasa, el runner global declara `enforced` en esa máquina; si no, queda en `configured`. Se aísla tras la etiqueta de compilación `linux`.

### 6.4 Gestión de procesos

```go
cmd := exec.CommandContext(ctx, bin, args...)
cmd.Env = scrubbedEnv(base, inv.Env)               // lista permitida
cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
cmd.Cancel = func() error {                        // SIGTERM al grupo completo
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
}
cmd.WaitDelay = 5 * time.Second // pasado el plazo, se remata el grupo con SIGKILL
```

Así los procesos descendientes terminan con el padre (RF-07, CA-10). La salida estándar se lee con un `io.LimitedReader`; si se excede `MaxOutput`, el motor se marca como fallido y la ejecución como incompleta, sin truncar de forma silenciosa.

---

## 7. Provisión de motores y bases

### 7.1 Manifiesto de confianza

Archivo `manifest/trust.json` embebido con `go:embed`. Se actualiza únicamente con un release de la CLI (PRD §6.7); nunca se resuelve `latest` en tiempo de ejecución.

```json
{
  "schema": 1,
  "engines": {
    "trivy": {
      "version": "X.Y.Z",
      "image": "ghcr.io/aquasecurity/trivy@sha256:...",
      "archives": {
        "linux-amd64":  { "url": "https://...", "sha256": "..." },
        "linux-arm64":  { "url": "https://...", "sha256": "..." },
        "darwin-amd64": { "url": "https://...", "sha256": "..." },
        "darwin-arm64": { "url": "https://...", "sha256": "..." }
      }
    }
  }
}
```

`tools/update-manifest` corre en CI: descarga los artefactos, verifica la firma y los checksums que publica el proyecto del motor y recién entonces escribe los hashes. En el equipo del usuario basta comparar el SHA-256 con el manifiesto, que viaja firmado dentro del release de la CLI. El artefacto se nombra como lo publica cada proyecto (`trivy_<versión>_macOS-ARM64.tar.gz`, `cargo-audit-aarch64-apple-darwin-v<versión>.tgz`, etc.).

**Versiones fijadas al iniciar H1** (verificadas en los spikes P-07 a P-11): Trivy 0.76.1, govulncheck v1.9.0, ESLint 10.13.0 con eslint-plugin-security 4.2.0 y @typescript-eslint/parser 8.72.1, Psalm 6.20.3, cargo-audit 0.22.2, Bandit 1.9.4. La versión de Semgrep se fija en H6.

**Política de actualización del motor.** El binario o la imagen se actualizan solo cuando la versión fijada en el manifiesto difiere de la instalada, y nunca durante un escaneo: la actualización es una tarea explícita, independiente de la actualización de bases (PRD §6.3). El estado de lo instalado vive en `state.json`, así que la comparación es directa. Un cambio de versión del motor exige repetir la validación de flags y la prueba de aislamiento por versión (sección 15.2).

### 7.2 Instalación del binario global

| Paso | Detalle |
| --- | --- |
| 1 | Resolver plataforma (`GOOS`/`GOARCH`) y buscar la entrada del manifiesto; sin entrada → error de plataforma (código 3) |
| 2 | Tomar el bloqueo exclusivo de instalación |
| 3 | Descargar a un directorio temporal en el **mismo sistema de archivos** que el destino, con tope de tamaño y tiempo |
| 4 | Verificar SHA-256 contra el manifiesto; si falla, borrar y detener (CA-29) |
| 5 | Extraer con `archive/tar` y `compress/gzip` **solo el binario esperado**; rechazar rutas absolutas, `..`, enlaces simbólicos y entradas fuera del nombre permitido |
| 6 | Aplicar permisos, comprobar `--version` contra el manifiesto y publicar con `os.Rename` |
| 7 | Registrar en `state.json`. La instalación previa válida permanece hasta que la nueva esté completa |

Nunca se ejecutan scripts remotos ni se invoca `sh` (PRD §6.3).

### 7.3 Perfil de shell (solo `setup` global)

Bloque delimitado, idempotente, con copia de respaldo y registro en `state.json`:

```sh
# >>> cgc-scan (no editar este bloque) >>>
export PATH="$HOME/.local/bin:$PATH"
# <<< cgc-scan <<<
```

La CLI detecta el intérprete por `$SHELL` (zsh, bash, fish) y elige el archivo adecuado. Si el bloque existe, no se duplica (CA-37). `scan` jamás toca perfiles (PRD §6.3).

### 7.4 Bases de datos y bloqueos

Cada fuente de datos implementa una interfaz común y `update-db` las recorre:

```go
type DBSource interface {
	ID() string // trivy-db, trivy-java-db, trivy-checks, rustsec, go-vulndb
	Update(ctx context.Context) (DBState, error)
	State(ctx context.Context) (DBState, error) // fecha, versión, esquema
}
```

Protocolo de exclusión mutua sobre `locks/trivy-cache.lock` (compartido por todas las ejecuciones de la CLI, no solo por un contenedor):

1. `scan` toma el bloqueo **exclusivo**, actualiza las bases y lo libera.
2. Toma el bloqueo **compartido** y lo mantiene durante todo el escaneo.
3. **Después** de tomar el compartido lee los metadatos de la base y los registra. Mientras exista algún bloqueo compartido nadie puede actualizar, así que la versión registrada es la usada (CA-39).
4. Las interrupciones se resuelven descargando a un directorio temporal y publicando con `os.Rename`, de modo que siempre queda una base válida (PRD §6.4).

Con `--offline` no se toma el bloqueo exclusivo ni se invoca ningún actualizador; se valida la antigüedad con los umbrales de `config.toml`.

---

## 8. Adaptadores

Las señales de detección por lenguaje están en PRD §5. Esta tabla fija cómo se invoca y se interpreta cada herramienta. Los flags exactos se confirman contra la versión fijada (tarea de validación previa a v1).

| Adaptador | Invocación prevista | Salida | Requisitos locales | Notas de normalización |
| --- | --- | --- | --- | --- |
| Trivy | `fs --format json` con los escáneres vuln, secret y misconfig | Un JSON con `Results[]` | Imagen o binario, bases | Un `Result` por objetivo (manifiesto, archivo). Los secretos se redactan en `Redact` antes de persistir |
| govulncheck | Modo fuente sobre el módulo, salida JSON, base local mediante su opción de base alternativa | Flujo de objetos JSON (config, osv, finding) leído con `json.Decoder` | Toolchain Go, módulos descargados, copia local de la base | Distingue dependencia presente de función alcanzable (se guarda en `Priority.Reachable`) |
| ESLint | Configuración propia fijada, sin búsqueda de configuración del proyecto, formato JSON | Arreglo JSON por archivo | Node, paquetes fijados | Cubre JavaScript y TypeScript; la regla y su gravedad vienen de nuestra configuración |
| Psalm | Configuración generada por la CLI, análisis de taint, salida JSON | Arreglo JSON | PHP, Composer, dependencias instaladas | Ruta de origen a sumidero se guarda en `Evidence` |
| cargo-audit | Opción de base local, sin actualización ni consultas adicionales | JSON | Binario, copia local de RustSec | Advisories de dependencias; tipo `vulnerability` |
| Bandit | Formato JSON sobre el árbol de código | JSON con `results[]` | Python | Severidad y confianza se conservan por separado |
| Semgrep CE (opcional) | Reglas locales, métricas y comprobación de versión desactivadas | JSON | Solo si `semgrep_enabled=true` | Estado `disabled` cuando no está habilitado (PRD §5.2) |

**Exclusiones.** Cada adaptador traduce el conjunto efectivo de exclusiones (sección 9.4) a los mecanismos de su motor: `--skip-dirs` y `--skip-files` en Trivy, `--ignore-pattern` en ESLint, rutas excluidas en Bandit, configuración generada en Psalm. Un adaptador que no pueda expresar una exclusión lo declara en `Requirements()` y la ejecución queda incompleta: nunca se acepta un motor que escanee contenido que la CLI declaró excluido.

**Candidatos de receta.** Cada adaptador conoce cómo se prueba y se construye su ecosistema, así que aporta los candidatos de receta que le corresponden: `go test ./...` y `go build ./...` en Go, los scripts de `package.json` en JavaScript y TypeScript, los de `composer.json` en PHP, `cargo test` y `cargo build` en Rust, `pytest` en Python. Son propuestas que el usuario confirma (sección 9.5); el adaptador nunca las publica por su cuenta como recetas de confianza.

### 8.1 Cómo se obtienen las herramientas de los adaptadores (decisión cerrada, D-01)

PRD §6.3 limita el aprovisionamiento automático a Trivy. La decisión **D-01** (`docs/decisiones-preparacion.md`) extiende el mecanismo de la sección 7 a las herramientas de los adaptadores, con las mismas garantías:

- Binarios publicados (cargo-audit, Psalm en `.phar`): descarga y verificación contra el manifiesto, igual que Trivy.
- Paquetes de ecosistema (ESLint y plugins, Bandit): instalación en `engines/<herramienta>/<versión>/` con el instalador del ecosistema **sin ejecutar scripts de instalación** (`--ignore-scripts` en npm; hashes requeridos en pip) y desde archivos de bloqueo con integridad.
- govulncheck: se enlaza como biblioteca (`golang.org/x/vuln/scan`), validado en P-10. Sigue necesitando el toolchain Go del usuario en modo fuente.
- Si falta el toolchain del ecosistema (Node, PHP, Python, Go, Rust), el adaptador se omite con `requirement_missing` y la ejecución es incompleta (PRD §5, regla común).
- Toda versión y hash se fijan en `manifest/trust.json`; nunca se resuelve `latest` y nunca se instala nada en el proyecto.

### 8.2 Normalización de severidad (Propuesto)

La escala común y el criterio de "mayor entre fuentes" están en PRD §9. Mapeo por motor:

| Motor | Original | Normalizada |
| --- | --- | --- |
| Trivy | CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN | `critical`, `high`, `medium`, `low`, `unknown` |
| Bandit | HIGH, MEDIUM, LOW, UNDEFINED (la confianza se guarda aparte) | `high`, `medium`, `low`, `unknown` |
| Semgrep | ERROR, WARNING, INFO (o impacto de la regla si lo declara) | `high`, `medium`, `info` |
| ESLint | Nivel de la regla en la configuración propia (sección 8.3) | Según la tabla de categorías de la sección 8.3 |
| Psalm | Tipo de problema de taintedness: sumidero alcanzado (sección 8.3) | Según la tabla de categorías de la sección 8.3 |
| govulncheck, cargo-audit | Sin severidad propia en muchos casos | `unknown`, salvo que el advisory la incluya |

### 8.3 Severidad de las reglas de código (ESLint y Psalm)

Las reglas de código no traen una severidad intrínseca: la asigna la configuración que genera la CLI, y esa asignación es versionada junto al resto de reglas. La tabla no enumera reglas sino **categorías de riesgo**, para que el listado sobreviva a los cambios de nombre de las reglas en el ecosistema:

| Categoría de riesgo | Alcance | Severidad normalizada |
| --- | --- | --- |
| Ejecución de código arbitrario | `eval` con expresión, procesos hijos, shell | `high` |
| Inyección | SQL, cabeceras, LDAP | `medium` |
| Rutas de archivo controladas por entrada | rutas no literales, lectura y escritura arbitrarias | `medium` |
| Carga y resolución dinámica de módulos | `require` no literal, inclusiones tainted | `medium` |
| Manipulación de prototipos y objetos | inyección de propiedades | `medium` |
| Denegación de servicio | expresiones regulares inseguras | `low` |
| Aleatoriedad no criptográfica | uso de PRNG en contexto de seguridad | `low` |
| Referencia informativa | reglas activadas solo como señal | `info` |

Tres reglas que fijan el comportamiento:

- **Una regla sin categoría no se activa.** La CLI no habilita reglas que no pueda clasificar, de modo que no aparece un `unknown` por descuido de configuración.
- **La asignación concreta de reglas a categorías se valida en el spike P-11** y se versiona con la configuración de reglas; la tabla anterior es el criterio, no el inventario cerrado.
- **La normalizada es la mayor entre las fuentes verificadas** (PRD §9). Una misma regla detectada por dos motores con severidades distintas se reporta con la mayor y conserva las diferencias.

`info` queda por debajo de `low` y no bloquea por sí sola; `unknown` no se descarta en silencio y su conteo contra el umbral lo decide la política, que deja la decisión registrada en `policy` (sección 9.3).

---

## 9. Normalización, correlación y política

### 9.1 Fingerprint

Identificador estable entre ejecuciones, independiente del número de línea:

```go
func Fingerprint(f *Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "v1|%s|%s", f.Kind, f.stableIdentity())
	return hex.EncodeToString(h.Sum(nil))[:32]
}
```

| Tipo | Identidad estable |
| --- | --- |
| Dependencia | ecosistema, nombre normalizado, versión, advisory canónico, ruta relativa del manifiesto |
| Código | regla normalizada, ruta relativa, hash del contexto circundante normalizado (sin espacios) |
| Secreto | tipo, ruta relativa, huella del valor (HMAC con sal por instalación) |
| Configuración | regla, ruta relativa, recurso afectado |

**Compromiso asumido:** la sal por instalación impide adivinar valores débiles a partir de un reporte compartido, pero hace que la comparación de secretos entre equipos distintos degrade a tipo más ruta (ADR-08).

### 9.2 Correlación

- **Dependencias:** componente (ecosistema, nombre, versión) más conjunto de alias del advisory (CVE, GHSA, GO-, RUSTSEC). Se unen hallazgos que comparten componente y al menos un alias, con estructura de conjuntos disjuntos.
- **Código:** misma clase de debilidad (CWE), ruta y hash de contexto.
- Nunca se une por título ni por número de línea. Se conservan todas las fuentes y las diferencias de severidad (RF-06, CA-07).

### 9.3 Política

`policy.Evaluate` recibe los hallazgos normalizados, el umbral efectivo y las excepciones, y devuelve incumplimientos y supresiones. Un hallazgo suprimido permanece en el reporte con su motivo. Las excepciones vencidas dejan de suprimir en la fecha indicada, evaluada en UTC (CA-12). El umbral del proyecto solo puede endurecer el de usuario o de la ejecución. La severidad `unknown` no se descarta en silencio: la política decide si cuenta contra el umbral y deja esa decisión registrada en `policy`. `info` queda por debajo de `low` y no bloquea por sí sola.

### 9.4 Selección de rutas y cobertura parcial

El alcance de un escaneo se calcula en un orden fijo, antes de descubrir unidades y de construir el plan:

```text
1. universo   ← raíz del proyecto (detectada) o, si no hay raíz, el directorio objetivo
2. incluir    ← si hay --include, el universo se restringe a lo que coincida con los patrones
3. intrínsecas← se excluyen siempre (node_modules, vendor, .venv, target, dist, build, .next, coverage, salidas propias)
4. usuario    ← exclusiones de config.toml
5. política   ← `exclude` del archivo de política del proyecto (solo agrega)
6. cli        ← si hay --exclude, REEMPLAZA los niveles 4 y 5; las intrínsecas del nivel 3 se conservan
7. resultado  ← las unidades que no sobreviven quedan en coverage.not_analyzed
```

Dos reglas fija el diseño y no son negociables:

- **Las exclusiones prevalecen sobre las inclusiones.** `--include 'src/**'` nunca reactiva contenido excluido por los niveles 3 a 6; de lo contrario un patrón mal escrito podría devolver `node_modules` al análisis.
- **Las exclusiones intrínsecas son absolutas.** Ni la CLI ni un archivo de política hostil pueden desactivarlas.

Precedencia por campo, heredada de PRD §6.8: los parámetros de la ejecución reemplazan a la política del proyecto, que reemplaza a la configuración de usuario, que reemplaza a los valores por defecto. La consecuencia no obvia es que `--exclude` puede **ampliar** la cobertura respecto del archivo del proyecto (la cobertura solo crece, lo que nunca oculta hallazgos), y que el recorte elegido queda registrado con su origen.

**Raíz del proyecto.** Para que "lo no analizado" sea enumerable, la CLI necesita un alcance mayor que el objetivo. La raíz se detecta por señales del propio ecosistema (`go.work`, `composer.json`, workspaces de `package.json`, raíz de Git) y es un dato de la *descubrimiento*, no de la selección. Si no se detecta ninguna, la raíz es el directorio objetivo y el escaneo no puede ser parcial por selección de rutas.

**Parcialidad.** `coverage.partial` es verdadero si y solo si hay una exclusión elegida (niveles 4 a 6) o una restricción por `--include`. Las exclusiones intrínsecas no lo activan: si lo hicieran, todo escaneo real sería parcial y la marca perdería valor. Cuando es verdadero, `coverage.not_analyzed` enumera las **unidades** no analizadas y los patrones aplicados, nunca listas de archivos.

**Propagación a los motores.** Un patrón de exclusión de archivo no se implementa solo en la CLI: si el motor no recibe la exclusión, escanea lo que la CLI declaró excluido y el reporte miente. El conjunto efectivo de exclusiones viaja en el plan hasta cada adaptador, que lo traduce a los mecanismos de su motor (`--skip-dirs`/`--skip-files` en Trivy, `--ignore-pattern` en ESLint, rutas excluidas en Bandit, entre otros). Un adaptador que no pueda expresar una exclusión lo declara en `Requirements()` y la ejecución queda incompleta, nunca silenciosamente sesgada.

### 9.5 Recetas de validación

Las recetas de tests y build son la única parte del prompt que el agente ejecuta. De dónde salen y quién las respalda define la frontera de confianza del prompt entero.

**Origen.** Viven en la configuración de usuario, fuera del proyecto, indexadas por raíz de proyecto (sección 4.2). El archivo de política del proyecto no puede establecerlas: PRD §6.8 lo trata como dato no confiable, y una receta que la CLI publica como confiable a partir de contenido del repositorio convierte ese contenido en instrucciones para el agente. La contradicción aparente entre PRD §6.8 (prohíbe comandos) y PRD §10.1 (exige configuración confiable) se resuelve de esta manera: el origen confiable es la configuración del usuario.

**Candidatos.** La CLI detecta candidatos leyendo los manifiestos del proyecto —scripts de `package.json` y `composer.json`, objetivos de `Makefile`, herramientas declaradas en `pyproject.toml`— y combinándolos con el stack que ya detectaron los adaptadores. Los candidatos se ofrecen **identificados como tales**: son propuestas, no recetas.

**Confirmación.** `cgc-scan recipes` lista candidatos y recetas confirmadas para el proyecto actual; `cgc-scan recipes --set <archivo>` confirma en la configuración de usuario las recetas declaradas en ese archivo; `--clear` las elimina. Confirmar es un acto explícito del usuario: desde ese momento la receta es de confianza y aparece en el prompt con su directorio de trabajo y su unidad afectada.

**Sin receta.** Si una unidad no tiene receta confirmada, el prompt la declara como campo sin resolver y la validación de esa unidad queda bloqueada (PRD §10.1). La CLI nunca inventa un comando ni afirma que se ejecutó.

**Registro.** Las recetas efectivas y las unidades que quedaron sin receta se registran en `validation` del reporte: son parte de la configuración efectiva (RF-12) y su ausencia o su cambio altera el resultado de la validación.

---

## 10. Reportes

### 10.1 JSON

El contrato de campos está en PRD §9. Estructura de nivel superior:

```json
{
  "schema_version": "1.0.0",
  "run": {},
  "target": {},
  "coverage": { "partial": false, "exclusions": [], "not_analyzed": [] },
  "tools": { "engines": [] },
  "isolation": { "level": "configured", "verified_by": "" },
  "validation": { "recipes": [], "unresolved": [] },
  "findings": [],
  "policy": {},
  "errors": []
}
```

**Forma mínima de las secciones.** El esquema se escribe a mano y es un contrato público (ADR-06), así que fija estas formas mínimas y ninguna sección puede omitirlas:

- `coverage`: `partial` (booleano, siempre presente), `exclusions` (cada exclusión con su origen), `not_analyzed` (unidades no analizadas; vacío cuando `partial` es falso) y el estado por unidad —solicitado, completado, omitido, fallido— (RF-02).
- `tools.engines`: una entrada por motor con su estado por unidad, de modo que se vea qué se pidió, qué se completó, qué se omitió y qué falló.
- `target`: identificador local, unidades detectadas, revisión Git si está disponible y el registro de cambios sin commit.
- `isolation`: `level` y `verified_by`; nunca se declara `enforced` sin haberlo logrado.
- `validation`: las recetas efectivas y las unidades que quedaron sin receta.

Determinismo (CA-45, CA-56):

- Los `findings` se ordenan por severidad normalizada, datos de priorización y fingerprint. Las listas internas se ordenan por clave estable.
- No se emiten mapas con orden no definido: `encoding/json` ordena las claves de los mapas, pero se prefieren slices ordenados.
- Los campos volátiles (`run.id`, fechas, duraciones) están agrupados en `run`, de modo que comparar el resto del documento es directo.
- El esquema se valida en cada prueba contra `schemas/report.schema.json`.

### 10.2 Separación stdout y stderr

El único código que escribe en stdout es el renderizador de `report`. Todo lo demás usa `slog` hacia stderr. Se refuerza con el linter `forbidigo` prohibiendo `fmt.Print*` y `os.Stdout` fuera de `report` (CA-08).

### 10.3 Formato prompt

Se genera con `text/template` y plantillas embebidas y versionadas (`templates/prompt/*.tmpl`). El contenido y el flujo por parche están en PRD §10; aquí se define cómo se protege la plantilla:

- **Datos no confiables en bloques delimitados con nonce.** Cada render genera un delimitador aleatorio; si algún dato lo contuviera, se regenera. Las instrucciones nunca se interpolan desde la evidencia.
- **Saneado de texto antes de insertar:** se eliminan caracteres de control (salvo salto de línea y tabulación), secuencias ANSI y caracteres Unicode de dirección (U+202A a U+202E, U+2066 a U+2069); se marcan los de ancho cero.
- **Sin comandos tomados de advisories.** Las recetas de pruebas y build salen solo de configuración explícita del proyecto (PRD §10.1).
- **Lotes (decisión abierta, PRD §15):** si el prompt supera un tamaño configurable, se divide por unidad de parche con un índice; nunca se trunca en silencio.

### 10.4 Texto

Salida legible para terminal: color solo con TTY y sin `NO_COLOR` (RF-32), resumen de cobertura antes del detalle y mensaje explícito cuando la ejecución es incompleta.

---

## 11. CLI y experiencia de terminal

El contrato de comandos, flags y códigos de salida está en PRD §8. Detalles de implementación:

- **Señales:** `signal.NotifyContext` sobre `SIGINT` y `SIGTERM`; el contexto cancelado recorre el orquestador, mata los grupos de procesos y produce el código 130 junto con un reporte parcial cuando sea posible.
- **Registro:** `slog` con handler de texto (por defecto) o JSON (`--log-format json`) hacia stderr. Los tipos sensibles implementan `slog.LogValuer` para no volcar secretos.
- **Progreso:** líneas simples a stderr; barras o animaciones solo si stderr es TTY.
- **Windows:** no se publican binarios nativos; en WSL2 se usa el binario de Linux (PRD §12).

### 11.1 Variables de entorno que lee la CLI

| Variable | Uso |
| --- | --- |
| `NO_COLOR` | Desactiva color |
| `CGC_SCAN_CONFIG_DIR`, `CGC_SCAN_DATA_DIR`, `CGC_SCAN_CACHE_DIR` | Sobrescriben ubicaciones |
| `CGC_SCAN_LOG_LEVEL` | `debug`, `info`, `warn`, `error` |
| `DOCKER_HOST`, `DOCKER_CONTEXT` | Solo se **leen para detectar contexto remoto** y rechazarlo; la CLI no los modifica |

La CLI **no** pasa su propio entorno a los motores (sección 6.2).

---

## 12. Concurrencia, timeouts y cancelación

| Aspecto | Diseño |
| --- | --- |
| Concurrencia | `errgroup` con `SetLimit(n)`; `n = min(GOMAXPROCS, 4)` por defecto (Propuesto, ajustar tras benchmarks) |
| Timeouts | `context.WithTimeout` por invocación y uno global; valores por defecto fijados con benchmarks (sección 15.4) |
| Cancelación | El contexto raíz propaga a cada `exec.Cmd`; `Cancel` y `WaitDelay` terminan el grupo (sección 6.4) |
| Resultados parciales | Cada adaptador devuelve su resultado aunque otro falle; el orquestador marca la ejecución incompleta (RF-08) |
| Memoria | Salidas de motores se escriben a disco (ya redactadas) y se parsean en flujo cuando el formato lo permite |
| Descubrimiento | `filepath.WalkDir` sobre un `os.Root`; los enlaces simbólicos no salen de la raíz autorizada. Antes se detecta la raíz del proyecto (`go.work`, `composer.json`, workspaces de `package.json`, raíz de Git) para poder enumerar lo no analizado (sección 9.4). Los archivos ignorados por Git se recorren para buscar secretos, con enmascarado, y quedan fuera del análisis de código (Propuesto, se cierra en P-04) |

---

## 13. Modelo de amenazas y seguridad de la CLI

| Amenaza | Vector | Mitigación técnica | Verificado por |
| --- | --- | --- | --- |
| Repositorio hostil: configuración | `cgc-scan.toml` malicioso | Lista de claves permitidas, descarte con error de política, solo endurece | CA-52, CA-53 |
| Repositorio hostil: rutas | Enlaces simbólicos o `..` que apuntan fuera del proyecto | `os.Root` y resolución con comprobación de prefijo | CA-14 |
| Repositorio hostil: ejecución | Hooks, plugins o configuración ejecutable del proyecto | Configuración de motores generada por la CLI; los motores no cargan plugins del repositorio | CA-11, CA-14 |
| Salida de motor maliciosa o enorme | JSON gigante, caracteres de control | Tope de bytes, parser tolerante, saneado, fuzzing | CA-20 |
| Cadena de suministro del motor | Descarga manipulada | SHA-256 contra manifiesto firmado, extracción segura, instalación atómica | CA-29 |
| Cadena de suministro de la CLI | Dependencia comprometida | Lockfile, `go mod verify`, escaneo propio, firmas y SBOM | CA-54 |
| Fuga de credenciales al motor | Variables de entorno, archivos de configuración del usuario | Entorno por lista permitida, HOME aislado | CA-03 |
| Fuga por red | Motor intenta conectarse | Docker sin red, o `configured` con verificación por `strace` | CA-03, CA-41 |
| Envenenamiento de caché | Otro usuario local modifica las bases | Directorios 0700 y volumen de nombre propio del usuario (`cgc-scan-trivy-cache-<uid>`), para que dos usuarios de un mismo daemon no lo compartan | CA-55 |
| Fuga por reportes | Reportes con código y secretos | Enmascarado, permisos 0600, huella con sal | CA-13, CA-55 |
| Inyección en el prompt | Evidencia con instrucciones | Bloques con nonce, saneado, plantilla fija | CA-20 |
| Receta de validación no confiable | El repositorio propone un comando que la CLI publica como receta de confianza | Las recetas viven en la configuración de usuario y solo tras confirmación; el archivo del proyecto no puede establecerlas (sección 9.5) | CA-57 |

---

## 14. Privacidad y Ley 21.719 (técnico)

El cumplimiento desde el negocio está en el PRD. La arquitectura aquí descrita aplica privacidad por diseño:

- **CGC no recibe datos.** No hay telemetría, cuentas ni servicios propios en v1; el código, los inventarios y los reportes no salen del equipo (PRD §1, principio 1).
- **Datos tratados localmente.** Los reportes pueden contener fragmentos de código, rutas y, eventualmente, datos personales presentes en el proyecto. Quedan en el equipo del usuario con permisos restrictivos, y los secretos se enmascaran.
- **Transferencias:** durante la **preparación** se descargan imágenes, binarios y bases desde fuentes públicas sin adjuntar datos del proyecto. No hay transferencia de datos personales hacia CGC.
- **Si se agrega más adelante** telemetría, licenciamiento en línea, cuentas o un servicio de reportes, se debe repetir el análisis de la Ley 21.719 (vigencia plena el 1 de diciembre de 2026) antes de implementarlo; esa funcionalidad cambiaría el rol de CGC frente a los datos.

> Este apartado describe decisiones técnicas, no es asesoría legal. Conviene revisarlo con un profesional si el producto cambia de alcance.

---

## 15. Pruebas, build y release

### 15.1 Pirámide de pruebas

| Nivel | Contenido | Herramienta |
| --- | --- | --- |
| Unitarias | Fingerprint, correlación, severidad, política, `Decide`, saneado, rutas | `testing`, tablas, `go-cmp` |
| Contrato | JSON contra el esquema y archivos de referencia, sin campos volátiles | `jsonschema`, `testdata/golden` |
| CLI de extremo a extremo | `setup`, `scan`, `compare`, códigos de salida | `testscript` |
| Fuzzing | Parsers de salida de cada motor, TOML de política, saneado | `go test -fuzz` |
| Integración | Motores reales sobre `testdata/fixtures` | Etiqueta `//go:build integration` |
| Aislamiento | Cero conexiones externas por versión fijada | Docker `--network none` y `strace` |

### 15.2 Prueba de aislamiento por versión de motor

Se ejecuta en CI al cambiar cualquier versión del manifiesto y antes de cada release:

1. Correr el escaneo del fixture con el runner global bajo `strace -f -e trace=connect`.
2. Fallar si aparece un `connect` a una dirección que no sea de bucle local.
3. Repetir con el runner Docker verificando `--network none` en la configuración efectiva del contenedor.

### 15.3 Calidad estática

`go vet`, `staticcheck`, `golangci-lint` con `gosec`, `errcheck` y `forbidigo`; `go test -race` en la matriz; `govulncheck` sobre la propia CLI.

### 15.4 Benchmarks

Antes de fijar timeouts y metas (PRD §2.1): proyectos pequeño, mediano y monorepo grande, con y sin caché de bases, en Linux y macOS (amd64 y arm64), con Docker y con runner global.

### 15.5 Release

GoReleaser con `-trimpath` y `CGO_ENABLED=0`; matriz `linux/darwin` × `amd64/arm64`; checksums; firma sin clave con cosign; SBOM CycloneDX; atestación de procedencia SLSA si el repositorio y la CI lo soportan. La verificación está documentada y se prueba con un artefacto real (CA-54).

---

## 16. Riesgos técnicos de implementación

Los riesgos de producto y regulatorios están en PRD §14 y no se repiten.

| ID | Riesgo | Impacto | Mitigación |
| --- | --- | --- | --- |
| T-01 | Los flags de Trivy cambian entre versiones | Alto | Constructor `trivyArgs` encapsulado, pruebas de referencia y validación obligatoria al actualizar el manifiesto. P-09 añadió `--skip-version-check`: sin él la comprobación de versión abre red |
| T-02 | Permisos de archivos del volumen Docker según usuario del contenedor y Docker Desktop | Medio | Resuelto en P-08: contenedor como root, sin `--user`, volumen por uid y `--read-only` (ADR-13) |
| T-03 | Montajes de solo lectura lentos en Docker Desktop sobre proyectos grandes | Medio | Benchmarks; recomendar la modalidad global para proyectos muy grandes |
| T-04 | Distribución de las herramientas de los adaptadores (O-1) | Alto | Resuelto en D-01: aprovisionamiento verificado extendido; implementación en H4-02 |
| T-05 | ESLint y Psalm pueden cargar código del proyecto durante el análisis | Medio | Configuración propia, sin plugins del repositorio, entorno mínimo, aislamiento de red |
| T-06 | Cambios en formatos de salida de los motores | Medio | Parsers tolerantes, fuzzing, archivos de referencia por versión fijada |
| T-07 | Bloqueos de archivo y conversión compartido/exclusivo | Bajo | Protocolo de la sección 7.4 (soltar y tomar de nuevo, leer metadatos después) |
| T-08 | Las exclusiones de archivo no llegan al motor: la CLI declara excluido un directorio y el motor lo escanea igual, con lo que el reporte miente | Alto | El conjunto efectivo de exclusiones viaja en el plan y cada adaptador lo traduce a los mecanismos de su motor (sección 9.4); un adaptador incapaz de expresarlo se omite con causa explícita |

---

## 17. Registro de decisiones técnicas

| ID | Decisión | Opción elegida | Opción descartada | Razón | Estado |
| --- | --- | --- | --- | --- | --- |
| ADR-01 | Lenguaje | Go | Rust, TypeScript | Binario único, compilación cruzada, procesos y concurrencia nativos | Confirmado |
| ADR-02 | Integración con Docker | Invocar el binario `docker` | SDK de Docker | Menos dependencias y superficie de supply chain; manejo de contextos | Propuesto |
| ADR-03 | Framework de CLI | `cobra` | Parser propio | Ayuda y completado ya resueltos | Propuesto |
| ADR-04 | Formato de configuración | TOML | YAML | Sin tipado implícito; más seguro para archivos no confiables (cierra la decisión abierta del PRD) | Propuesto |
| ADR-05 | Distribución de adaptadores | Compilados en el binario, sin plugins dinámicos | Plugins | Menos superficie de ataque, builds reproducibles | Propuesto |
| ADR-06 | Esquema del reporte | Escrito a mano y embebido | Generado desde structs | Es un contrato público; los cambios deben ser deliberados | Propuesto |
| ADR-07 | Manifiesto de motores | Embebido, verificado en CI, hashes en el binario | Resolver versiones al ejecutar | Reproducibilidad y defensa ante descargas manipuladas | Propuesto |
| ADR-08 | Huella de secretos | HMAC con sal por instalación | SHA-256 sin sal | Evita adivinar valores débiles desde reportes compartidos; degrada la comparación entre equipos | Propuesto |
| ADR-09 | Salida de Trivy en Docker | Por stdout del contenedor | Directorio de salida montado | Menos montajes, menor superficie | Propuesto |
| ADR-10 | Confinamiento de rutas | `os.Root` (Go ≥ 1.24) | Comprobación manual de prefijos | La biblioteca estándar lo garantiza frente a enlaces y `..` | Propuesto |
| ADR-11 | Enlace global de Trivy | Enlace simbólico al motor versionado | Copiar el binario sobre `PATH` | Actualización atómica y sin pisar instalaciones ajenas | Propuesto |
| ADR-12 | Comprobación de versión de Trivy durante el escaneo | `--skip-version-check` obligatorio | Confiar en `--offline-scan` | P-09: sin el flag, Trivy contacta `check.trivy.dev` y `configured` sería falso | Confirmado |
| ADR-13 | Usuario del contenedor Trivy | root dentro del contenedor (sin `--user`) | uid del host | P-08: el volumen del daemon no es escribible por otro uid y no se pide elevación | Confirmado |
| ADR-14 | govulncheck | Biblioteca `golang.org/x/vuln/scan` | Binario externo | P-10: elimina un artefacto y reutiliza el parser; el toolchain Go sigue siendo requisito | Confirmado |
| ADR-15 | Repositorio y CI | GitHub público + GitHub Actions | Repositorio privado + claves propias | Habilita cosign sin clave y SLSA; el producto debe ser verificable por terceros | Confirmado (D-02) |
| ADR-16 | Nombre y licencia de la CLI | `cgc-scan`, Apache-2.0 | Nombre alternativo | Paquetes, dominios y repositorio libres; licencia compatible con todo el stack (D-03, D-06) | Confirmado; INAPI se verifica en H7-06 |
| ADR-17 | Herramientas de adaptadores | Aprovisionamiento verificado extendido (D-01) | Instalación manual o con los gestores del proyecto | Cobertura reproducible sin ejecutar scripts ni tocar el proyecto | Confirmado |

---

## 18. Hitos de ingeniería y preguntas abiertas

### 18.1 Orden de construcción

Complementa la secuencia de PRD §16 con el orden técnico. El desglose de tareas, dependencias y esfuerzo de cada hito vive en `workload.md` §3 y es la fuente autoritativa del plan; esta tabla resume el entregable y los criterios que cada hito valida.

| Hito | Entregable | Valida |
| --- | --- | --- |
| H0 | Repositorio, CI, linters, estructura de paquetes, `main` y `Decide` con pruebas, esquema del reporte y esqueleto de comandos | Base y disciplina de stdout/stderr |
| H1 | Rebanada vertical: `scan` sobre fixture Go con Trivy global, JSON válido contra el esquema | Contrato, runner global, normalización mínima |
| H2 | Runner Docker, volumen de caché, bloqueos y actualización de bases, `--offline` | PRD §6.2 a §6.4, CA-27, CA-28, CA-38 a CA-41 |
| H3 | `setup` completo (interactivo y no interactivo), perfil de shell, `state.json`, `doctor` y política del proyecto | CA-31, CA-33 a CA-37, CA-52, CA-53 |
| H4 | Adaptadores por lenguaje (resolver O-1 antes), descubrimiento de monorepos y raíz de proyecto, severidad de reglas, correlación, selección de rutas y cobertura parcial | CA-01, CA-02, CA-06, CA-07, CA-10, CA-11, CA-14, CA-46 |
| H5 | Política, excepciones, `compare`, formato prompt, `--report-out`, priorización y recetas de validación | CA-09, CA-12, CA-15 a CA-23, CA-45, CA-56, CA-57 |
| H6 | Semgrep opcional, pruebas de aislamiento por versión, release firmado con SBOM | CA-47 a CA-50, CA-54 |
| H7 | Benchmarks, endurecimiento, revisión de seguridad propia, matriz completa de aceptación, documentación y publicación de v1.0.0 | CA-01 a CA-56 |

### 18.2 Preguntas abiertas

| ID | Pregunta | Estado |
| --- | --- | --- |
| O-1 | ¿Cómo se obtienen las herramientas de los adaptadores? | **Cerrada (D-01):** aprovisionamiento verificado extendido, sin scripts de instalación (ADR-17) |
| O-2 | ¿Se enlaza govulncheck como biblioteca? | **Cerrada (P-10):** sí, `golang.org/x/vuln/scan` (ADR-14) |
| O-3 | Usuario del contenedor y propiedad del volumen (T-02) | **Cerrada (P-08):** root dentro del contenedor, sin `--user`, volumen por uid (ADR-13) |
| O-4 | Nombre y ubicación definitivos del archivo de política del proyecto | **Cerrada (D-04):** `cgc-scan.toml` en la raíz detectada |
| O-5 | ¿Se publica la CLI con repositorio público o privado? Define el uso de SLSA y de firmas sin clave | **Cerrada (D-02):** repositorio público + GitHub Actions (ADR-15) |
