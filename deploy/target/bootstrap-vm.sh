#!/bin/sh
# bootstrap-vm.sh: prepara uma VM para o pve-patcher. Roda como root, uma vez (idempotente).
#
#   curl -fsSL http://<app>/bootstrap-vm.sh | sh -s -- --pubkey "ssh-ed25519 AAAA... pve-patcher" [--user patcher] [--from 172.22.0.0/16]
#
# Cria o usuario (padrao "patcher"), autoriza a chave do app e grava um sudoers que libera SO:
#   - refresh e upgrade completo do gerenciador de pacotes (comandos e argumentos fixos);
#   - o reboot;
#   - /usr/local/sbin/patcher-upgrade (upgrade seletivo; valida os nomes de pacote).
# O patcher-agent continua indo pelo stdin a cada execucao, sem sudo; so esses passos usam "sudo -n".
# Os comandos aqui precisam bater com os do patcher-agent (mude os dois juntos).
#
# Auto-contido: o patcher-upgrade vai embutido no heredoc ao final (o app gera o script final com
# BootstrapScript.Render, que substitui o marcador do heredoc).
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

USER_NAME=patcher
PUBKEY=
FROM=
WRAPPER=/usr/local/sbin/patcher-upgrade
OLD_AGENT=/usr/local/sbin/patcher-agent

die() { echo "bootstrap: $1" >&2; exit 1; }
log() { echo "bootstrap: $1"; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --pubkey) [ "$#" -ge 2 ] || die "--pubkey requer valor"; PUBKEY=$2; shift 2 ;;
        --pubkey-file) [ "$#" -ge 2 ] || die "--pubkey-file requer valor"; PUBKEY=$(head -n 1 "$2"); shift 2 ;;
        --user) [ "$#" -ge 2 ] || die "--user requer valor"; USER_NAME=$2; shift 2 ;;
        --from) [ "$#" -ge 2 ] || die "--from requer valor"; FROM=$2; shift 2 ;;
        *) die "argumento desconhecido: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "execute como root"
[ -n "$PUBKEY" ] || die "informe --pubkey ou --pubkey-file"

# Validacoes (os valores entram em authorized_keys e sudoers).
printf '%s\n' "$USER_NAME" | grep -Eq '^[a-z_][a-z0-9_-]{0,31}$' || die "nome de usuario invalido"
[ "$USER_NAME" != root ] || die "--user root nao faz sentido: o objetivo e uma conta sem root"
printf '%s\n' "$PUBKEY" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) [A-Za-z0-9+/=]+( [^"]*)?$' \
    || die "chave publica invalida (esperado uma linha de chave OpenSSH)"
if [ -n "$FROM" ]; then
    printf '%s\n' "$FROM" | grep -Eq '^[0-9A-Fa-f:./,*?!-]+$' || die "--from invalido"
fi

ids=$( ( . /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}" ) || true )
case " $ids " in
    *" debian "*|*" ubuntu "*) FAMILY=apt ;;
    *" rhel "*|*" fedora "*|*" centos "*|*" almalinux "*|*" rocky "*) FAMILY=dnf ;;
    *" alpine "*) FAMILY=apk ;;
    *) die "distro nao suportada: $ids" ;;
esac

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

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
    [ "$(id -u "$USER_NAME")" -ne 0 ] || die "$USER_NAME tem uid 0"
    log "usuario $USER_NAME ja existe"
else
    log "criando usuario $USER_NAME"
    case "$FAMILY" in
        apk) adduser -D -s /bin/sh -g "pve-patcher" "$USER_NAME" ;;
        *) useradd -m -s /bin/sh -c "pve-patcher" "$USER_NAME" ;;
    esac
fi
# Conta sem senha mas nao bloqueada ("!" faz o sshd recusar chave sem PAM): troca por "*".
if [ -f /etc/shadow ]; then
    sed -i "s/^\($USER_NAME\):!\{1,\}[^:]*:/\1:*:/" /etc/shadow
fi

HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || die "home de $USER_NAME nao encontrado"
GROUP=$(id -gn "$USER_NAME")

# --- authorized_keys (troca a linha desta chave, preserva as demais) ---
OPTS="no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty"
[ -z "$FROM" ] || OPTS="from=\"$FROM\",$OPTS"
KEYBODY=$(printf '%s\n' "$PUBKEY" | awk '{ print $1 " " $2 }')
AK="$HOME_DIR/.ssh/authorized_keys"
mkdir -p "$HOME_DIR/.ssh"
[ -f "$AK" ] || : > "$AK"
grep -vF "$KEYBODY" "$AK" > "$TMP_DIR/ak" || true
printf '%s %s\n' "$OPTS" "$PUBKEY" >> "$TMP_DIR/ak"
cat "$TMP_DIR/ak" > "$AK"
chown -R "$USER_NAME:$GROUP" "$HOME_DIR/.ssh"
chmod 700 "$HOME_DIR/.ssh"
chmod 600 "$AK"
log "authorized_keys atualizado"

# --- patcher-upgrade (wrapper do upgrade seletivo) ---
emit_embedded_wrapper() {
    cat <<'PATCHER_UPGRADE_EOF'
@@PATCHER_UPGRADE@@
PATCHER_UPGRADE_EOF
}
emit_embedded_wrapper > "$TMP_DIR/wrapper"
head -n 1 "$TMP_DIR/wrapper" | grep -q '^#!/bin/sh' || die "patcher-upgrade ausente ou corrompido (gere o script com BootstrapScript.Render)"
sh -n "$TMP_DIR/wrapper" || die "patcher-upgrade com erro de sintaxe"
install -m 0755 -o root -g root "$TMP_DIR/wrapper" "$WRAPPER"
log "instalado $WRAPPER"

# Sobra do modelo antigo (agent instalado na VM): o app agora envia o agent pelo stdin.
if [ -f "$OLD_AGENT" ] && head -n 3 "$OLD_AGENT" | grep -q 'patcher-agent'; then
    rm -f "$OLD_AGENT"
    log "removido $OLD_AGENT (nao e mais usado)"
fi

# --- sudoers ---
bin_path() { command -v "$1" 2>/dev/null || die "$1 nao encontrado"; }
# Escapa os caracteres especiais do sudoers nos argumentos (\ , : =).
sudo_esc() { printf '%s' "$1" | sed 's/[\\,:=]/\\&/g'; }
# Caminho + argumentos exatos. Sem argumentos o sudoers aceitaria qualquer um: use "" para "nenhum".
cmnd() {
    out=$1
    shift
    for a in "$@"; do out="$out $(sudo_esc "$a")"; done
    printf '%s' "$out"
}

case "$FAMILY" in
    apt)
        APT=$(bin_path apt-get)
        CMDS="$(cmnd "$APT" -q -o Dpkg::Use-Pty=0 update), $(cmnd "$APT" -y -q -o Dpkg::Use-Pty=0 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade)" ;;
    dnf)
        DNF=$(bin_path dnf)
        CMDS="$(cmnd "$DNF" -q makecache), $(cmnd "$DNF" -y upgrade)" ;;
    apk)
        APK=$(bin_path apk)
        CMDS="$(cmnd "$APK" update), $(cmnd "$APK" upgrade --no-progress)" ;;
esac
if [ -d /run/systemd/system ]; then
    REBOOT=$(cmnd "$(bin_path systemctl)" reboot)
else
    REBOOT="$(bin_path reboot) \"\""
fi

mkdir -p /etc/sudoers.d
chmod 755 /etc/sudoers.d
SUDOERS_TMP=/etc/sudoers.d/.patcher.tmp
cat > "$SUDOERS_TMP" <<EOF
# Gerado pelo bootstrap-vm.sh do pve-patcher. Nao edite: rode o bootstrap de novo.
Defaults:$USER_NAME !requiretty
Defaults:$USER_NAME env_keep += "DEBIAN_FRONTEND NEEDRESTART_MODE APT_LISTCHANGES_FRONTEND"
$USER_NAME ALL=(root) NOPASSWD: $CMDS, $REBOOT, $WRAPPER
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
log "sudoers configurado (/etc/sudoers.d/$USER_NAME)"

command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ] || log "AVISO: openssh-server nao encontrado; instale e habilite o sshd"

log "pronto. $USER_NAME pode rodar como root apenas:"
sudo -l -U "$USER_NAME" | sed -n '/may run the following/,$p'
