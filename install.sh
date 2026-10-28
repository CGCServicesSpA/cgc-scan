#!/bin/sh
# Instalador local de CGC Scan.
#
# Uso desde el repositorio:
#   ./install.sh                 # compila, empaqueta en dist/ e instala en ~/.local/bin
#   ./install.sh --prefix DIR    # instala en otro directorio
#   ./install.sh --package       # crea el tar.gz de prueba local y lo instala
#   ./install.sh --from FILE     # instala un tar.gz ya generado
#   ./install.sh --uninstall     # elimina el binario instalado
#
# También funciona desde un paquete ya extraído: si hay un binario cgc-scan
# junto al script, lo instala sin compilar.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEFAULT_VERSION="0.1.0-rc.3"

if [ -n "${CGC_SCAN_VERSION:-}" ]; then
    VERSION=$CGC_SCAN_VERSION
elif [ -f "$SCRIPT_DIR/VERSION" ]; then
    VERSION=$(tr -d '[:space:]' < "$SCRIPT_DIR/VERSION")
else
    VERSION=$DEFAULT_VERSION
fi

PREFIX=${PREFIX:-"$HOME/.local/bin"}
ACTION=install
PACKAGE=0
BACKUP=1
FROM=""
BINARY=""
FORCE_BUILD=0

usage() {
    cat <<'EOF'
CGC Scan — instalador local

  ./install.sh [opciones]

Opciones:
  --prefix DIR       Directorio de instalación (por defecto ~/.local/bin)
  --version VERSION  Versión a compilar/verificar (por defecto VERSION)
  --package          Genera dist/cgc-scan_<versión>_<os>_<arch>.tar.gz + SHA-256
  --from ARCHIVO     Instala el binario de un tar.gz generado con --package
  --binary ARCHIVO   Instala un binario ya compilado
  --build            Fuerza la compilación desde el código fuente
  --no-backup        No conserva el binario anterior como .bak
  --uninstall        Elimina el binario instalado (no toca la configuración)
  -h, --help         Muestra esta ayuda

Variables:
  PREFIX, CGC_SCAN_VERSION, DIST_DIR
EOF
}

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        die "no hay sha256sum ni shasum disponibles"
    fi
}

detect_os() {
    case "$(uname -s)" in
        Darwin) echo darwin ;;
        Linux) echo linux ;;
        *) echo unknown ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        arm64|aarch64) echo arm64 ;;
        x86_64|amd64) echo amd64 ;;
        *) echo unknown ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            [ $# -ge 2 ] || die "--prefix requiere un directorio"
            PREFIX=$2
            shift 2
            ;;
        --prefix=*)
            PREFIX=${1#--prefix=}
            shift
            ;;
        --version)
            [ $# -ge 2 ] || die "--version requiere un valor"
            VERSION=$2
            shift 2
            ;;
        --version=*)
            VERSION=${1#--version=}
            shift
            ;;
        --package)
            PACKAGE=1
            shift
            ;;
        --from)
            [ $# -ge 2 ] || die "--from requiere un archivo"
            FROM=$2
            shift 2
            ;;
        --from=*)
            FROM=${1#--from=}
            shift
            ;;
        --binary)
            [ $# -ge 2 ] || die "--binary requiere un archivo"
            BINARY=$2
            shift 2
            ;;
        --binary=*)
            BINARY=${1#--binary=}
            shift
            ;;
        --build)
            FORCE_BUILD=1
            shift
            ;;
        --no-backup)
            BACKUP=0
            shift
            ;;
        --uninstall)
            ACTION=uninstall
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Opción desconocida: %s\n\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

TARGET=$PREFIX/cgc-scan

if [ "$ACTION" = uninstall ]; then
    if [ -e "$TARGET" ]; then
        rm -f "$TARGET"
        printf 'Eliminado %s\n' "$TARGET"
    else
        printf 'No hay binario instalado en %s\n' "$TARGET"
    fi
    printf 'La configuración y las cachés de usuario no se han tocado.\n'
    exit 0
fi

mkdir -p "$PREFIX"
TMP_BIN=$(mktemp "$PREFIX/.cgc-scan.tmp.XXXXXX")
TMP_DIR=""
cleanup() {
    rm -f "$TMP_BIN"
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

build_from_source() {
    command -v go >/dev/null 2>&1 || die "Go no está instalado; instala Go 1.27.3 o usa --from"
    GOVER=$(go env GOVERSION 2>/dev/null | sed 's/^go//')
    MAJOR=${GOVER%%.*}
    REST=${GOVER#*.}
    MINOR=${REST%%.*}
    if [ "${MAJOR:-0}" -lt 1 ] || { [ "${MAJOR:-0}" -eq 1 ] && [ "${MINOR:-0}" -lt 27 ]; }; then
        die "se requiere Go 1.27 o superior para compilar (detectado: ${GOVER:-desconocido})"
    fi
    COMMIT=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo local)
    BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf 'Compilando CGC Scan %s (commit %s)...\n' "$VERSION" "$COMMIT"
    (
        cd "$SCRIPT_DIR"
        CGO_ENABLED=0 go build -trimpath \
            -ldflags "-s -w \
              -X github.com/CGCServicesSpA/cgc-scan/internal/version.Version=$VERSION \
              -X github.com/CGCServicesSpA/cgc-scan/internal/version.Commit=$COMMIT \
              -X github.com/CGCServicesSpA/cgc-scan/internal/version.BuildDate=$BUILD_DATE" \
            -o "$TMP_BIN" ./cmd/cgc-scan
    ) || die "la compilación falló"
}

extract_from_archive() {
    [ -f "$FROM" ] || die "no existe el archivo $FROM"
    TMP_DIR=$(mktemp -d)
    tar -xzf "$FROM" -C "$TMP_DIR" || die "no se pudo extraer $FROM"
    FOUND=$(find "$TMP_DIR" -type f -name cgc-scan | head -n 1)
    [ -n "$FOUND" ] || die "el archivo no contiene un binario cgc-scan"
    cp "$FOUND" "$TMP_BIN"
    chmod 0755 "$TMP_BIN"
}

if [ -n "$FROM" ]; then
    extract_from_archive
elif [ -n "$BINARY" ]; then
    [ -f "$BINARY" ] || die "no existe el binario $BINARY"
    cp "$BINARY" "$TMP_BIN"
    chmod 0755 "$TMP_BIN"
elif [ "$FORCE_BUILD" -eq 0 ] && [ -x "$SCRIPT_DIR/cgc-scan" ] && [ ! -f "$SCRIPT_DIR/go.mod" ]; then
    # Paquete extraído: se instala el binario que acompaña al script.
    cp "$SCRIPT_DIR/cgc-scan" "$TMP_BIN"
    chmod 0755 "$TMP_BIN"
else
    build_from_source
fi

# Verificación mínima: la versión pedida y el esquema del reporte deben
# responder antes de tocar la instalación actual.
ACTUAL=$("$TMP_BIN" --version 2>/dev/null || true)
case "$ACTUAL" in
    *"$VERSION"*) ;;
    *) die "el binario no responde con la versión $VERSION: ${ACTUAL:-sin salida}" ;;
esac
case "$ACTUAL" in
    *"esquema 1.0.0"*) ;;
    *) die "el binario no declara el esquema 1.0.0: $ACTUAL" ;;
esac

if [ "$PACKAGE" -eq 1 ]; then
    OS=$(detect_os)
    ARCH=$(detect_arch)
    [ "$OS" != unknown ] || die "sistema operativo no soportado"
    [ "$ARCH" != unknown ] || die "arquitectura no soportada"
    DIST=${DIST_DIR:-"$SCRIPT_DIR/dist"}
    NAME="cgc-scan_${VERSION}_${OS}_${ARCH}"
    STAGE=$(mktemp -d)
    TMP_DIR=$STAGE
    mkdir -p "$STAGE/$NAME" "$DIST"
    cp "$TMP_BIN" "$STAGE/$NAME/cgc-scan"
    chmod 0755 "$STAGE/$NAME/cgc-scan"
    for f in install.sh VERSION LICENSE README.md SECURITY.md THIRD_PARTY_NOTICES.md; do
        [ -f "$SCRIPT_DIR/$f" ] && cp "$SCRIPT_DIR/$f" "$STAGE/$NAME/$f"
    done
    cat > "$STAGE/$NAME/INSTALL.txt" <<EOF
CGC Scan $VERSION — paquete local

Instalar en el usuario actual (sin sudo):
  ./install.sh

Instalar en otro prefijo:
  ./install.sh --prefix /ruta/bin

Verificar:
  cgc-scan --version
  cgc-scan doctor --format json

Primera configuración:
  cgc-scan setup
EOF
    tar -czf "$DIST/$NAME.tar.gz" -C "$STAGE" "$NAME"
    SUM=$(sha256 "$DIST/$NAME.tar.gz")
    printf '%s  %s\n' "$SUM" "$NAME.tar.gz" > "$DIST/$NAME.tar.gz.sha256"
    printf 'Paquete: %s\nSHA-256: %s\n' "$DIST/$NAME.tar.gz" "$SUM"
fi

if [ -e "$TARGET" ] && [ "$BACKUP" -eq 1 ]; then
    mv -f "$TARGET" "$TARGET.bak"
fi
chmod 0755 "$TMP_BIN"
mv -f "$TMP_BIN" "$TARGET"
INSTALLED_SHA=$(sha256 "$TARGET")

printf '\nInstalado: %s\n' "$TARGET"
printf 'Versión:   %s\n' "$VERSION"
printf 'SHA-256:   %s\n' "$INSTALLED_SHA"
case ":$PATH:" in
    *":$PREFIX:"*) ;;
    *) printf 'Aviso: %s no está en PATH; añádelo a tu perfil de shell.\n' "$PREFIX" ;;
esac
printf '\nSiguiente paso: cgc-scan setup\n'
