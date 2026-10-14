#!/bin/sh
# bootstrap-vm.sh: prepara uma VM para o pve-patcher. Roda como root, uma vez (idempotente).
#
#   sh bootstrap-vm.sh --pubkey "ssh-ed25519 AAAA... patcher" [--user patcher] [--from 172.22.0.0/16]
#   sh bootstrap-vm.sh --pubkey-file chave.pub [--agent-file ./patcher-agent]
#
# Auto-contido: o patcher-agent vai embutido no heredoc ao final (a UI/servidor gera o script
# final com BootstrapScript.Render, que substitui o marcador do heredoc).
# Para usar o arquivo cru do repositorio, passe --agent-file explicitamente (nunca e procurado sozinho).
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

USER_NAME=patcher
PUBKEY=
FROM=
AGENT_FILE=
DEST=/usr/local/sbin/patcher-agent

die() { echo "bootstrap: $1" >&2; exit 1; }
log() { echo "bootstrap: $1"; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --pubkey) [ "$#" -ge 2 ] || die "--pubkey requer valor"; PUBKEY=$2; shift 2 ;;
        --pubkey-file) [ "$#" -ge 2 ] || die "--pubkey-file requer valor"; PUBKEY=$(head -n 1 "$2"); shift 2 ;;
        --user) [ "$#" -ge 2 ] || die "--user requer valor"; USER_NAME=$2; shift 2 ;;
        --from) [ "$#" -ge 2 ] || die "--from requer valor"; FROM=$2; shift 2 ;;
        --agent-file) [ "$#" -ge 2 ] || die "--agent-file requer valor"; AGENT_FILE=$2; shift 2 ;;
        *) die "argumento desconhecido: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "execute como root"
[ -n "$PUBKEY" ] || die "informe --pubkey ou --pubkey-file"

# Validacoes (os valores entram em authorized_keys e sudoers).
printf '%s\n' "$USER_NAME" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "nome de usuario invalido"
printf '%s\n' "$PUBKEY" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) [A-Za-z0-9+/=]+( [^"]*)?$' \
    || die "chave publica invalida (esperado uma linha de chave OpenSSH)"
if [ -n "$FROM" ]; then
    printf '%s\n' "$FROM" | grep -Eq '^[0-9A-Fa-f:./,*?!-]+$' || die "--from invalido"
fi

# Familia pela command line (os-release so confirma).
ids=$( ( . /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}" ) || true )
case " $ids " in
    *" debian "*|*" ubuntu "*) FAMILY=apt ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" almalinux "*|*" rocky "*) FAMILY=dnf ;;
    *" alpine "*) FAMILY=apk ;;
    *) die "distro nao suportada: $ids" ;;
esac

# --- sudo ---
if ! command -v sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then
    log "instalando sudo"
    case "$FAMILY" in
        apt) DEBIAN_FRONTEND=noninteractive apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q sudo ;;
        dnf) dnf -y install sudo ;;
        apk) apk add --no-progress sudo ;;
    esac
fi

# --- usuario ---
if id "$USER_NAME" >/dev/null 2>&1; then
    log "usuario $USER_NAME ja existe"
else
    log "criando usuario $USER_NAME"
    case "$FAMILY" in
        apk) adduser -D -s /bin/sh "$USER_NAME" ;;
        apt) useradd -m -s /bin/sh -c "pve-patcher" "$USER_NAME" ;;
        dnf) useradd -m -s /bin/sh -c "pve-patcher" "$USER_NAME" ;;
    esac
fi
# Conta sem senha mas nao bloqueada ("!" faz o sshd recusar chave sem PAM): troca por "*".
if [ -f /etc/shadow ]; then
    sed -i "s/^\($USER_NAME\):!\{1,\}[^:]*:/\1:*:/" /etc/shadow
fi

HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || die "home de $USER_NAME nao encontrado"
GROUP=$(id -gn "$USER_NAME")

# --- authorized_keys ---
OPTS="no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty"
[ -z "$FROM" ] || OPTS="from=\"$FROM\",$OPTS"
mkdir -p "$HOME_DIR/.ssh"
printf '%s %s\n' "$OPTS" "$PUBKEY" > "$HOME_DIR/.ssh/authorized_keys"
chown -R "$USER_NAME:$GROUP" "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"
chmod 600 "$HOME_DIR/.ssh/authorized_keys"
log "authorized_keys atualizado"

# --- agent ---
TMP_AGENT=$(mktemp)
trap 'rm -f "$TMP_AGENT"' EXIT
emit_embedded_agent() {
    cat <<'PATCHER_AGENT_EOF'
@@PATCHER_AGENT@@
PATCHER_AGENT_EOF
}

if [ -n "$AGENT_FILE" ]; then
    cat "$AGENT_FILE" > "$TMP_AGENT"
else
    emit_embedded_agent > "$TMP_AGENT"
fi
head -n 1 "$TMP_AGENT" | grep -q '^#!/bin/sh' || die "patcher-agent ausente ou corrompido (gere o script com BootstrapScript.Render ou use --agent-file)"
sh -n "$TMP_AGENT" || die "patcher-agent com erro de sintaxe"
install -m 0755 -o root -g root "$TMP_AGENT" "$DEST"
log "instalado $DEST"

# --- sudoers ---
mkdir -p /etc/sudoers.d
chmod 755 /etc/sudoers.d
SUDOERS_TMP=/etc/sudoers.d/.patcher.tmp
cat > "$SUDOERS_TMP" <<EOF
$USER_NAME ALL=(root) NOPASSWD: $DEST
Defaults:$USER_NAME !requiretty
EOF
chmod 0440 "$SUDOERS_TMP"
if ! visudo -cf "$SUDOERS_TMP" >/dev/null; then
    rm -f "$SUDOERS_TMP"
    die "sudoers invalido, abortado"
fi
mv "$SUDOERS_TMP" "/etc/sudoers.d/$USER_NAME"
# Alguns sudoers minimos (Alpine) nao incluem o diretorio.
if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d' /etc/sudoers; then
    printf '@includedir /etc/sudoers.d\n' >> /etc/sudoers
    visudo -c >/dev/null || die "/etc/sudoers invalido apos incluir sudoers.d"
fi
log "sudoers configurado"

command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || log "AVISO: openssh-server nao encontrado; instale e habilite o sshd"

"$DEST" version
log "pronto: usuario $USER_NAME pode rodar apenas $DEST via sudo"
