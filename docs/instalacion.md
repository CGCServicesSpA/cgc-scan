# Instalación

CGC Scan se distribuye como un binario estático para macOS y Linux (amd64 y
arm64). Windows se usa mediante WSL2.

## Requisitos

| Componente | Cuándo hace falta |
| --- | --- |
| Docker local o conexión a internet | Preparación inicial de Trivy, bases e imágenes de toolchain |
| Go 1.27.3 | Solo para compilar desde fuente; con Docker el adaptador de Go corre en su imagen |
| Node 20+ | Solo sin Docker: adaptadores JavaScript y TypeScript (ESLint) |
| PHP 8.2+ y Composer | Solo sin Docker: adaptador PHP (Psalm). `composer install` es siempre un paso previo del usuario |
| Rust/Cargo | Solo sin Docker: adaptador Rust (cargo-audit); la base RustSec la prepara la CLI |
| Python 3.10+ | Solo sin Docker: adaptador Python (Bandit) |

Con Docker local, CGC Scan detecta la versión que declara el proyecto y ejecuta
cada adaptador dentro de una imagen derivada de la imagen oficial del lenguaje;
no hace falta instalar los toolchains en el equipo. Sin Docker se usan los del
host y, si falta uno, el adaptador se omite con `requirement_missing`, la
cobertura lo declara y el código de salida es 3.

La primera ejecución con Docker descarga la imagen base del lenguaje (entre
cientos de MB y ~1 GB según el lenguaje) y construye una imagen derivada por
combinación lenguaje/versión/motor. Las siguientes reutilizan imagen y volumen
de caché. En CI, construye las imágenes una vez con red y luego usa
`--offline`; las imágenes viven en el daemon del runner, no en el proyecto.

## Desde un release

1. Descarga el archivo de tu plataforma y `checksums.txt`.
2. Verifica la firma y el checksum ([procedimiento](verificacion-release.md)).
3. Descomprime y coloca `cgc-scan` en un directorio de tu `PATH`.

```bash
tar -xzf cgc-scan_<versión>_darwin_arm64.tar.gz
sudo install -m 0755 cgc-scan /usr/local/bin/cgc-scan
cgc-scan --version
```

## Desde el código

```bash
git clone https://github.com/CGCServicesSpA/cgc-scan.git
cd cgc-scan
./install.sh
```

`install.sh` compila con la versión de `VERSION`, verifica que el binario
responda con esa versión y el esquema vigente (lo lee de
`schemas/report.schema.json`), y lo instala de forma atómica en `~/.local/bin`
(o en `--prefix`). Conserva el binario anterior como `cgc-scan.bak`.

Después actualiza la skill global de agentes con `scripts/install-skill.sh`:

```bash
./install.sh --no-skill            # solo el binario
./install.sh --skill-target all    # binario + skill en todos los harness
```

El paquete generado con `--package` incluye `scripts/install-skill.sh` y
`skills/cgc-scan/`, así que el mismo instalador actualiza la skill sin depender
del repositorio. `--uninstall` elimina solo el binario; la skill se quita con
`./scripts/install-skill.sh --uninstall`.

Para probar el flujo de paquete:

```bash
./install.sh --package
# deja dist/cgc-scan_<versión>_<os>_<arch>.tar.gz y su .sha256
mkdir -p /tmp/cgc-install && tar -xzf dist/cgc-scan_*.tar.gz -C /tmp/cgc-install
/tmp/cgc-install/cgc-scan_*/install.sh --prefix /tmp/cgc-bin
```

Ese `install.sh` empaquetado instala el binario que lo acompaña sin Go ni red y
actualiza la skill global incluida en el paquete.
También se puede instalar un artefacto ya generado:

```bash
./install.sh --from dist/cgc-scan_<versión>_<os>_<arch>.tar.gz
```

Para desarrollo sin instalar:

```bash
go build -trimpath -o cgc-scan ./cmd/cgc-scan
./cgc-scan --version
```

La CI usa la versión de Go de `go.mod` (directiva `toolchain`). `CGO_ENABLED=0`
produce el binario estático de release.

## Primera configuración

```bash
cgc-scan setup
```

`setup` detecta Docker y pregunta si Trivy se usa como contenedor o como binario
global. Si Docker no está operativo, explica la causa y ofrece la instalación
global. Después pregunta si habilitar Semgrep CE (opcional, desactivado por
defecto).

Sin terminal o desde un gestor de paquetes:

```bash
cgc-scan setup --trivy-mode docker --semgrep disable --non-interactive
cgc-scan setup --trivy-mode global --non-interactive
cgc-scan setup --trivy-mode docker --semgrep enable --non-interactive
```

La elección se guarda en la configuración de usuario y no se vuelve a preguntar.
Una selección explícita (`--trivy-mode`) manda sobre la guardada; no hay fallback
silencioso si el runner elegido deja de funcionar.

## Qué modifica `setup`

- `<config>/cgc-scan/config.toml` y `<data>/cgc-scan/state.json` con permisos 0600.
- En modalidad global: el binario Trivy verificado en `<data>/cgc-scan/engines/`,
  un enlace en `~/.local/bin/trivy` (nunca pisa un binario ajeno) y un bloque
  idempotente en el perfil de shell (`.zshrc`, `.bashrc`/`.bash_profile` o
  `config.fish`) con copia de respaldo.
- En modalidad Docker: el volumen `cgc-scan-trivy-cache-<uid>` y la imagen fijada
  por digest.

Nunca escribe en el proyecto ni pide `sudo`. Si cancelas, no se guarda una
configuración a medias.

## Desinstalar

```bash
# binario y datos locales
rm -f ~/.local/bin/trivy
rm -rf ~/.config/cgc-scan ~/.local/share/cgc-scan ~/.cache/cgc-scan
```

En macOS las rutas son `~/Library/Application Support/cgc-scan` (config y datos)
y `~/Library/Caches/cgc-scan`. El bloque del perfil de shell se elimina a mano
(está delimitado por los marcadores `cgc-scan`). Los volúmenes Docker se borran
con `docker volume rm cgc-scan-trivy-cache-<uid>` solo si estás seguro de que no
se usan.
