#!/bin/sh
# Instalador local de CGC Scan.
#
# Uso desde el repositorio:
#   ./install.sh                 # compila, empaqueta en dist/ e instala en ~/.local/bin
#   ./install.sh --prefix DIR    # instala en otro directorio
#   ./install.sh --package       # crea el tar.gz de prueba local y lo instala
#   ./install.sh --from FILE     # instala un tar.gz ya generado
#   ./install.sh --uninstall     # elimina el binario instalado
#   ./install.sh --no-skill      # no instala ni actualiza la skill global
#
# También funciona desde un paquete ya extraído: si hay un binario cgc-scan
# junto al script, lo instala sin compilar.
#
# Tras instalar el binario, actualiza la skill global con scripts/install-skill.sh
# (incluido en el paquete) para que los agentes usen la versión de la CLI.

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
SKILL=1
SKILL_TARGET=auto
SKILL_SOURCE=""
SKILL_SCRIPT=""

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
  --no-skill         No instala ni actualiza la skill global
  --skill-target MODE
                     Destino de la skill (auto|all|agents|opencode|devpass|
                     claude|codex|kiro|mcode|pi|DIR); por defecto auto
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
        --no-skill)
            SKILL=0
            shift
            ;;
        --skill-target)
            [ $# -ge 2 ] || die "--skill-target requiere un valor"
            SKILL_TARGET=$2
            shift 2
            ;;
        --skill-target=*)
            SKILL_TARGET=${1#--skill-target=}
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
    printf 'La skill global no se elimina; usa scripts/install-skill.sh --uninstall si quieres quitarla.\n'
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
    # El paquete incluye la skill y su instalador; se usan desde la extracción.
    SKILL_SOURCE=$(find "$TMP_DIR" -type d -path '*/skills/cgc-scan' | head -n 1)
    SKILL_SCRIPT=$(find "$TMP_DIR" -type f -path '*/scripts/install-skill.sh' | head -n 1)
}

# locate_skill resuelve la skill y su instalador en el repositorio o en un
# paquete extraído. No falla si no están: se avisa y el binario ya quedó.
locate_skill() {
    if [ -z "$SKILL_SOURCE" ] && [ -f "$SCRIPT_DIR/skills/cgc-scan/SKILL.md" ]; then
        SKILL_SOURCE="$SCRIPT_DIR/skills/cgc-scan"
    fi
    if [ -z "$SKILL_SCRIPT" ] && [ -f "$SCRIPT_DIR/scripts/install-skill.sh" ]; then
        SKILL_SCRIPT="$SCRIPT_DIR/scripts/install-skill.sh"
    fi
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

locate_skill

# Verificación mínima: la versión pedida y el esquema del reporte deben
# responder antes de tocar la instalación actual.
ACTUAL=$("$TMP_BIN" --version 2>/dev/null || true)
case "$ACTUAL" in
    *"$VERSION"*) ;;
    *) die "el binario no responde con la versión $VERSION: ${ACTUAL:-sin salida}" ;;
esac
# El esquema no se fija a mano: se acepta cualquier versión semántica y, si el
# repositorio trae el esquema, se exige la que declara ese archivo.
if ! printf '%s\n' "$ACTUAL" | grep -Eq 'esquema [0-9]+\.[0-9]+\.[0-9]+'; then
    die "el binario no declara el esquema del reporte: $ACTUAL"
fi
# Los esquemas públicos viajan con el paquete y se verifican todos: la
# validación no se omite silenciosamente por ausencia de esquema.
SCHEMAS_DIR="$SCRIPT_DIR/schemas"
if [ ! -d "$SCHEMAS_DIR" ]; then
    die "el paquete no trae el directorio schemas/ con los esquemas públicos"
fi
for SCHEMA in report.schema.json agent.schema.json audit-ledger.schema.json findings.schema.json; do
    SCHEMA_FILE="$SCHEMAS_DIR/$SCHEMA"
    if [ ! -f "$SCHEMA_FILE" ]; then
        die "el paquete no trae el esquema público $SCHEMA"
    fi
    NAME=$(basename "$SCHEMA" .schema.json)
    VER=$(grep -o "${NAME}-[0-9][0-9.]*" "$SCHEMA_FILE" | head -n 1 | sed 's/\.\{1,\}$//' || true)
    case "$NAME" in
        report)
            REPORT_VER=${VER#report-}
            if [ -n "$REPORT_VER" ] && ! printf '%s\n' "$ACTUAL" | grep -Fq "esquema $REPORT_VER"; then
                die "el binario no declara el esquema del reporte $REPORT_VER: $ACTUAL"
            fi
            ;;
        *)
            if [ -n "$VER" ] && ! printf '%s\n' "$ACTUAL" | grep -Fq "$VER"; then
                die "el binario no declara el contrato $VER que exige el esquema $SCHEMA: $ACTUAL"
            fi
            ;;
    esac
done

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
    # Los cuatro esquemas públicos viajan con el paquete: el instalador
    # verifica la concordancia entre esquemas, binario y versión sin
    # depender del checkout original.
    if [ -d "$SCRIPT_DIR/schemas" ]; then
        mkdir -p "$STAGE/$NAME/schemas"
        for s in report.schema.json agent.schema.json audit-ledger.schema.json findings.schema.json; do
            [ -f "$SCRIPT_DIR/schemas/$s" ] || die "falta el esquema público $s"
            cp "$SCRIPT_DIR/schemas/$s" "$STAGE/$NAME/schemas/$s"
        done
    else
        die "el checkout no trae schemas/; el paquete debe ser autosuficiente"
    fi
    # La skill y su instalador viajan con el paquete para que install.sh pueda
    # actualizarla sin depender del repositorio.
    if [ -f "$SCRIPT_DIR/scripts/install-skill.sh" ]; then
        mkdir -p "$STAGE/$NAME/scripts"
        cp "$SCRIPT_DIR/scripts/install-skill.sh" "$STAGE/$NAME/scripts/install-skill.sh"
        chmod 0755 "$STAGE/$NAME/scripts/install-skill.sh"
    fi
    if [ -d "$SCRIPT_DIR/skills/cgc-scan" ]; then
        mkdir -p "$STAGE/$NAME/skills"
        cp -R "$SCRIPT_DIR/skills/cgc-scan" "$STAGE/$NAME/skills/cgc-scan"
    fi
    cat > "$STAGE/$NAME/INSTALL.txt" <<EOF
CGC Scan $VERSION — paquete local

Instalar en el usuario actual (sin sudo):
  ./install.sh

Instalar en otro prefijo:
  ./install.sh --prefix /ruta/bin

El instalador actualiza también la skill global de agentes. Para omitirla:
  ./install.sh --no-skill

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

if [ "$SKILL" -eq 1 ]; then
    if [ -n "$SKILL_SOURCE" ] && [ -n "$SKILL_SCRIPT" ] && [ -f "$SKILL_SOURCE/SKILL.md" ]; then
        printf '\nActualizando la skill global (destino: %s)...\n' "$SKILL_TARGET"
        if ! sh "$SKILL_SCRIPT" --source "$SKILL_SOURCE" --target "$SKILL_TARGET"; then
            printf 'Aviso: no se pudo actualizar la skill; ejecuta scripts/install-skill.sh.\n' >&2
        fi
    else
        printf '\nAviso: no se encontró la skill en este paquete; instálala con scripts/install-skill.sh.\n' >&2
    fi
else
    printf '\nSkill: omitida por --no-skill.\n'
fi

printf '\nSiguiente paso: cgc-scan setup\n'
