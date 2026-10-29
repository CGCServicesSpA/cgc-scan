#!/bin/sh
# Instala, actualiza, comprueba o elimina la skill global de CGC Scan.
#
# Uso:
#   ./scripts/install-skill.sh                 # detecta DevPass/OpenCode y Claude
#   ./scripts/install-skill.sh --target all
#   ./scripts/install-skill.sh --target opencode
#   ./scripts/install-skill.sh --target claude
#   ./scripts/install-skill.sh --target DIR    # DIR es la raíz de skills
#   ./scripts/install-skill.sh --status
#   ./scripts/install-skill.sh --check
#   ./scripts/install-skill.sh --uninstall
#
# Variables: SKILLS_DIR (raíz de skills), NO_BACKUP=1.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=${SOURCE_DIR:-"$SCRIPT_DIR/../skills/cgc-scan"}
TARGET_MODE=${TARGET_MODE:-auto}
TARGET_DIR=""
ACTION=install
BACKUP=${NO_BACKUP:-0}
DRY_RUN=0
FORCE=0

usage() {
    cat <<'EOF'
CGC Scan — instalador de la skill global

  ./scripts/install-skill.sh [opciones]

Opciones:
  --target auto|opencode|claude|all|DIR
                     Destino. auto detecta DevPass/OpenCode y Claude.
                     DIR se interpreta como raíz de skills (instala DIR/cgc-scan).
  --source DIR       Directorio de la skill (por defecto skills/cgc-scan).
  --status           Muestra la versión instalada en cada destino.
  --check            Sale con 1 si la versión instalada no coincide con la fuente.
  --uninstall        Elimina la skill de los destinos.
  --no-backup        No conserva la versión anterior como cgc-scan.bak.
  --force            Permite reemplazar/eliminar un directorio ajeno.
  --dry-run          Muestra lo que haría sin escribir.
  -h, --help         Muestra esta ayuda.

Variables:
  SKILLS_DIR         Si está definida, se usa como único destino.
  NO_BACKUP=1        Equivale a --no-backup.
EOF
}

die() {
    printf 'install-skill.sh: %s\n' "$*" >&2
    exit 1
}

skill_version() {
    sed -n 's/^version:[[:space:]]*//p' "$1" | head -n 1 | tr -d '\r'
}

is_ours() {
    [ -f "$1/SKILL.md" ] && grep -q '^name:[[:space:]]*cgc-scan' "$1/SKILL.md"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target)
            [ $# -ge 2 ] || die "--target requiere un valor"
            TARGET_MODE=$2
            shift 2
            ;;
        --target=*)
            TARGET_MODE=${1#--target=}
            shift
            ;;
        --source)
            [ $# -ge 2 ] || die "--source requiere un directorio"
            SOURCE_DIR=$2
            shift 2
            ;;
        --source=*)
            SOURCE_DIR=${1#--source=}
            shift
            ;;
        --status)
            ACTION=status
            shift
            ;;
        --check)
            ACTION=check
            shift
            ;;
        --uninstall)
            ACTION=uninstall
            shift
            ;;
        --no-backup)
            BACKUP=0
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
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

[ -f "$SOURCE_DIR/SKILL.md" ] || die "no existe $SOURCE_DIR/SKILL.md"
grep -q '^name:[[:space:]]*cgc-scan' "$SOURCE_DIR/SKILL.md" || die "la fuente no es la skill cgc-scan"
SOURCE_VERSION=$(skill_version "$SOURCE_DIR/SKILL.md")
[ -n "$SOURCE_VERSION" ] || die "la skill no declara version en el frontmatter"

ROOTS=""
add_root() {
    [ -n "$1" ] || return 0
    case " $ROOTS " in
        *" $1 "*) ;;
        *) ROOTS="$ROOTS $1" ;;
    esac
}

if [ -n "${SKILLS_DIR:-}" ]; then
    add_root "$SKILLS_DIR"
else
    case "$TARGET_MODE" in
        auto)
            [ -d "$HOME/.config/opencode" ] && add_root "$HOME/.config/opencode/skills"
            [ -d "$HOME/.claude" ] && add_root "$HOME/.claude/skills"
            ;;
        opencode) add_root "$HOME/.config/opencode/skills" ;;
        claude) add_root "$HOME/.claude/skills" ;;
        all)
            add_root "$HOME/.config/opencode/skills"
            add_root "$HOME/.claude/skills"
            ;;
        *)
            TARGET_DIR=$TARGET_MODE
            add_root "$TARGET_DIR"
            ;;
    esac
fi

[ -n "$ROOTS" ] || die "no se detectó ningún harness; usa --target DIR o SKILLS_DIR"

if [ "$ACTION" = status ] || [ "$ACTION" = check ]; then
    rc=0
    for root in $ROOTS; do
        dest=$root/cgc-scan
        if [ -f "$dest/SKILL.md" ]; then
            installed=$(skill_version "$dest/SKILL.md")
            printf '%s: %s\n' "$dest" "${installed:-sin versión}"
            if [ "$ACTION" = check ] && [ "$installed" != "$SOURCE_VERSION" ]; then
                printf '  esperado: %s\n' "$SOURCE_VERSION"
                rc=1
            fi
        else
            printf '%s: no instalada\n' "$dest"
            [ "$ACTION" = check ] && rc=1
        fi
    done
    exit $rc
fi

if [ "$ACTION" = uninstall ]; then
    for root in $ROOTS; do
        dest=$root/cgc-scan
        if [ ! -e "$dest" ]; then
            printf '%s: no instalada\n' "$dest"
            continue
        fi
        if ! is_ours "$dest" && [ "$FORCE" -eq 0 ]; then
            die "$dest no parece la skill cgc-scan; usa --force para eliminarla"
        fi
        if [ "$DRY_RUN" -eq 1 ]; then
            printf 'eliminaría %s\n' "$dest"
            continue
        fi
        rm -rf "$dest"
        rm -rf "$dest.bak"
        printf 'eliminada %s\n' "$dest"
    done
    exit 0
fi

# install / update
for root in $ROOTS; do
    dest=$root/cgc-scan
    if [ -e "$dest" ] && ! is_ours "$dest" && [ "$FORCE" -eq 0 ]; then
        die "$dest ya existe y no parece la skill cgc-scan; usa --force"
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'instalaría %s (%s) en %s\n' "$SOURCE_DIR" "$SOURCE_VERSION" "$dest"
        continue
    fi
    mkdir -p "$root"
    stage=$(mktemp -d "$root/.cgc-scan-skill.XXXXXX")
    cp -R "$SOURCE_DIR/." "$stage/"
    chmod -R u+rwX,go+rX "$stage"
    if [ -e "$dest" ]; then
        if [ "$BACKUP" -eq 1 ]; then
            rm -rf "$dest.bak"
            mv "$dest" "$dest.bak"
        else
            rm -rf "$dest"
        fi
    fi
    if ! mv "$stage" "$dest"; then
        [ -e "$dest.bak" ] && mv "$dest.bak" "$dest"
        die "no se pudo publicar $dest"
    fi
    printf 'instalada %s %s en %s\n' cgc-scan "$SOURCE_VERSION" "$dest"
done
