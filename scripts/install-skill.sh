#!/bin/sh
# Instala, actualiza, comprueba o elimina la skill global de CGC Scan.
#
# La fuente canónica es ~/.agents/skills/cgc-scan. OpenCode y Claude se enlazan
# a esa copia, de modo que actualizar una vez actualiza todos los harness.
#
# Uso:
#   ./scripts/install-skill.sh                 # auto: agents + harness detectados
#   ./scripts/install-skill.sh --target all    # agents + OpenCode + Claude
#   ./scripts/install-skill.sh --target agents # solo agents
#   ./scripts/install-skill.sh --target opencode
#   ./scripts/install-skill.sh --target claude
#   ./scripts/install-skill.sh --target DIR    # modo directo en DIR/cgc-scan
#   ./scripts/install-skill.sh --status
#   ./scripts/install-skill.sh --check
#   ./scripts/install-skill.sh --uninstall
#
# Variables: SKILLS_DIR (destino directo), AGENTS_SKILLS_DIR, NO_BACKUP=1.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_DIR=${SOURCE_DIR:-"$SCRIPT_DIR/../skills/cgc-scan"}
TARGET_MODE=${TARGET_MODE:-auto}
AGENTS_ROOT=${AGENTS_SKILLS_DIR:-"$HOME/.agents/skills"}
OPENCODE_ROOT=${OPENCODE_SKILLS_DIR:-"$HOME/.config/opencode/skills"}
CLAUDE_ROOT=${CLAUDE_SKILLS_DIR:-"$HOME/.claude/skills"}
CUSTOM_ROOT=""
ACTION=install
BACKUP=${NO_BACKUP:-0}
DRY_RUN=0
FORCE=0
USE_CANONICAL=0

LINK_ROOTS=""
add_link_root() {
    [ -n "$1" ] || return 0
    case " $LINK_ROOTS " in
        *" $1 "*) ;;
        *) LINK_ROOTS="$LINK_ROOTS $1" ;;
    esac
}

usage() {
    cat <<'EOF'
CGC Scan — instalador de la skill global

  ./scripts/install-skill.sh [opciones]

Opciones:
  --target auto|all|agents|opencode|claude|DIR
                     auto: ~/.agents/skills + harness detectados.
                     all: agents + OpenCode + Claude.
                     agents: solo ~/.agents/skills.
                     DIR: modo directo, instala DIR/cgc-scan sin enlaces.
  --source DIR       Directorio de la skill (por defecto skills/cgc-scan).
  --status           Muestra la versión instalada y los enlaces.
  --check            Sale con 1 si falta o la versión no coincide.
  --uninstall        Elimina la copia canónica y los enlaces.
  --no-backup        No conserva la versión anterior como cgc-scan.bak.
  --force            Permite reemplazar/eliminar un directorio ajeno.
  --dry-run          Muestra lo que haría sin escribir.
  -h, --help         Muestra esta ayuda.

Variables:
  SKILLS_DIR          Destino directo, sin enlaces.
  AGENTS_SKILLS_DIR   Raíz canónica (por defecto ~/.agents/skills).
  OPENCODE_SKILLS_DIR Raíz de skills de OpenCode (para pruebas/instalaciones).
  CLAUDE_SKILLS_DIR   Raíz de skills de Claude (para pruebas/instalaciones).
  NO_BACKUP=1         Equivale a --no-backup.
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

if [ -n "${SKILLS_DIR:-}" ]; then
    CUSTOM_ROOT=$SKILLS_DIR
else
    case "$TARGET_MODE" in
        agents)
            USE_CANONICAL=1
            ;;
        auto)
            USE_CANONICAL=1
            [ -d "$HOME/.config/opencode" ] && add_link_root "$OPENCODE_ROOT"
            [ -d "$HOME/.claude" ] && add_link_root "$CLAUDE_ROOT"
            ;;
        all)
            USE_CANONICAL=1
            add_link_root "$OPENCODE_ROOT"
            add_link_root "$CLAUDE_ROOT"
            ;;
        opencode)
            USE_CANONICAL=1
            add_link_root "$OPENCODE_ROOT"
            ;;
        claude)
            USE_CANONICAL=1
            add_link_root "$CLAUDE_ROOT"
            ;;
        *)
            CUSTOM_ROOT=$TARGET_MODE
            ;;
    esac
fi

[ "$USE_CANONICAL" -eq 1 ] || [ -n "$CUSTOM_ROOT" ] || die "destino no válido"

install_copy() {
    root=$1
    dest=$root/cgc-scan
    if [ -e "$dest" ] && [ ! -L "$dest" ] && ! is_ours "$dest" && [ "$FORCE" -eq 0 ]; then
        die "$dest ya existe y no parece la skill cgc-scan; usa --force"
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'instalaría %s (%s) en %s\n' "$SOURCE_DIR" "$SOURCE_VERSION" "$dest"
        return 0
    fi
    mkdir -p "$root"
    stage=$(mktemp -d "$root/.cgc-scan-skill.XXXXXX")
    cp -R "$SOURCE_DIR/." "$stage/"
    chmod -R u+rwX,go+rX "$stage"
    if [ -e "$dest" ] || [ -L "$dest" ]; then
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
}

link_skill() {
    root=$1
    dest=$root/cgc-scan
    target=$AGENTS_ROOT/cgc-scan
    if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$target" ]; then
        printf 'enlace %s -> %s (sin cambios)\n' "$dest" "$target"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'enlazaría %s -> %s\n' "$dest" "$target"
        return 0
    fi
    mkdir -p "$root"
    if [ -e "$dest" ] || [ -L "$dest" ]; then
        if ! is_ours "$dest" && [ "$FORCE" -eq 0 ]; then
            die "$dest ya existe y no parece la skill cgc-scan; usa --force"
        fi
        if [ "$BACKUP" -eq 1 ]; then
            rm -rf "$dest.bak"
            mv "$dest" "$dest.bak"
        else
            rm -rf "$dest"
        fi
    fi
    tmp="$dest.tmp-cgc-scan"
    rm -f "$tmp"
    ln -s "$target" "$tmp"
    mv -f "$tmp" "$dest"
    printf 'enlazada %s -> %s\n' "$dest" "$target"
}

show_path() {
    dest=$1
    if [ -L "$dest" ] && [ -f "$dest/SKILL.md" ]; then
        printf '%s -> %s: %s\n' "$dest" "$(readlink "$dest")" "$(skill_version "$dest/SKILL.md")"
        return 0
    fi
    if [ -f "$dest/SKILL.md" ]; then
        printf '%s: %s\n' "$dest" "$(skill_version "$dest/SKILL.md")"
        return 0
    fi
    printf '%s: no instalada\n' "$dest"
    return 1
}

remove_path() {
    dest=$1
    if [ ! -e "$dest" ] && [ ! -L "$dest" ]; then
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'eliminaría %s\n' "$dest"
        return 0
    fi
    if ! is_ours "$dest" && [ "$FORCE" -eq 0 ]; then
        die "$dest no parece la skill cgc-scan; usa --force para eliminarla"
    fi
    rm -rf "$dest"
    rm -rf "$dest.bak"
    printf 'eliminada %s\n' "$dest"
}

if [ "$ACTION" = status ] || [ "$ACTION" = check ]; then
    rc=0
    if [ "$USE_CANONICAL" -eq 1 ]; then
        show_path "$AGENTS_ROOT/cgc-scan" || { [ "$ACTION" = check ] && rc=1; }
        for root in $LINK_ROOTS; do
            show_path "$root/cgc-scan" || { [ "$ACTION" = check ] && rc=1; }
        done
    else
        show_path "$CUSTOM_ROOT/cgc-scan" || { [ "$ACTION" = check ] && rc=1; }
    fi
    if [ "$ACTION" = check ]; then
        for path in "$AGENTS_ROOT/cgc-scan" "$CUSTOM_ROOT/cgc-scan"; do
            [ -n "$path" ] || continue
            [ -f "$path/SKILL.md" ] || continue
            if [ "$(skill_version "$path/SKILL.md")" != "$SOURCE_VERSION" ]; then
                printf '%s: esperado %s\n' "$path" "$SOURCE_VERSION"
                rc=1
            fi
        done
        for root in $LINK_ROOTS; do
            path="$root/cgc-scan"
            [ -f "$path/SKILL.md" ] || continue
            if [ "$(skill_version "$path/SKILL.md")" != "$SOURCE_VERSION" ]; then
                printf '%s: esperado %s\n' "$path" "$SOURCE_VERSION"
                rc=1
            fi
        done
    fi
    exit $rc
fi

if [ "$ACTION" = uninstall ]; then
    if [ "$USE_CANONICAL" -eq 1 ]; then
        # Elimina los enlaces que apunten a la copia canónica, aunque no se
        # hayan seleccionado explícitamente.
        for root in $OPENCODE_ROOT $CLAUDE_ROOT $LINK_ROOTS; do
            dest=$root/cgc-scan
            if [ -L "$dest" ]; then
                case "$(readlink "$dest")" in
                    "$AGENTS_ROOT/cgc-scan"|"$AGENTS_ROOT/cgc-scan"/*) remove_path "$dest" ;;
                esac
            fi
        done
        remove_path "$AGENTS_ROOT/cgc-scan"
    else
        remove_path "$CUSTOM_ROOT/cgc-scan"
    fi
    exit 0
fi

# install / update
if [ "$USE_CANONICAL" -eq 1 ]; then
    install_copy "$AGENTS_ROOT"
    for root in $LINK_ROOTS; do
        link_skill "$root"
    done
else
    install_copy "$CUSTOM_ROOT"
fi
