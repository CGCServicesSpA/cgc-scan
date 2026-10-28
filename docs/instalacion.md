# Instalación

CGC Scan se distribuye como un binario estático para macOS y Linux (amd64 y
arm64). Windows se usa mediante WSL2.

## Requisitos

| Componente | Cuándo hace falta |
| --- | --- |
| Docker local o conexión a internet | Preparación inicial de Trivy y bases |
| Go 1.27.3 | Adaptador de Go (`govulncheck`) y compilar desde fuente |
| Node 20+ | Adaptadores JavaScript y TypeScript (ESLint) |
| PHP 8.2+ y Composer | Adaptador PHP (Psalm) |
| Rust/Cargo | Adaptador Rust (cargo-audit); la base RustSec la prepara la CLI |
| Python 3.10+ | Adaptador Python (Bandit) |

Los toolchains no se instalan automáticamente. Si falta uno, el adaptador se
omite con `requirement_missing`, la cobertura lo declara y el código de salida
es 3.

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
