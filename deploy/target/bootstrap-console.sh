#!/bin/sh
# bootstrap-console.sh: confere e ajusta a conta do Terminal SSH do pve-patcher. Roda como root (idempotente).
#
#   curl -fsSL http://<app>/bootstrap-console.sh | sh -s -- --pubkey "ssh-ed25519 AAAA... pve-console" --user heber
#
# A conta precisa existir (local, LDAP/SSSD...): o script NAO cria usuario. Para cada item imprime
# "ok:" (ja estava certo), "ajustado:" (corrigido agora) ou "AVISO:" (precisa de acao manual):
#   - conta bloqueada sem senha ("!" no shadow faz o sshd recusar chave sem PAM) -> "*";
#   - permissoes do home, ~/.ssh e authorized_keys (StrictModes do sshd);
#   - a chave do terminal no authorized_keys, sem no-pty/restrict/command= (o terminal precisa de PTY);
#   - sudo sem senha: se "sudo -n" falhar, grava /etc/sudoers.d/zz-pve-patcher-console com NOPASSWD: ALL;
#   - configuracao do sshd que impeca o login (so avisa).
# Com --user root so a chave e o sshd sao conferidos.
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

USER_NAME=
PUBKEY=
SUDOERS=/etc/sudoers.d/zz-pve-patcher-console
ADJ=0
WARN=0

die() { echo "bootstrap-console: $1" >&2; exit 1; }
ok() { echo "ok: $1"; }
fixed() { echo "ajustado: $1"; ADJ=$((ADJ + 1)); }
warn() { echo "AVISO: $1"; WARN=$((WARN + 1)); }

while [ "$#" -gt 0 ]; do
    case "$1" in
        --pubkey) [ "$#" -ge 2 ] || die "--pubkey requer valor"; PUBKEY=$2; shift 2 ;;
        --pubkey-file) [ "$#" -ge 2 ] || die "--pubkey-file requer valor"; PUBKEY=$(head -n 1 "$2"); shift 2 ;;
        --user) [ "$#" -ge 2 ] || die "--user requer valor"; USER_NAME=$2; shift 2 ;;
        *) die "argumento desconhecido: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "execute como root"
[ -n "$PUBKEY" ] || die "informe --pubkey ou --pubkey-file"
[ -n "$USER_NAME" ] || die "informe --user"

# Validacoes (os valores entram em authorized_keys e sudoers). O regex do usuario e o mesmo da tela de Configuracoes.
printf '%s\n' "$USER_NAME" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$' || die "nome de usuario invalido"
printf '%s\n' "$PUBKEY" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) [A-Za-z0-9+/=]+( [^"]*)?$' \
    || die "chave publica invalida (esperado uma linha de chave OpenSSH)"

PW=$(getent passwd "$USER_NAME") || die "usuario $USER_NAME nao existe nesta VM (crie a conta antes; o bootstrap do terminal nao cria usuarios)"
U_UID=$(id -u "$USER_NAME")
U_GID=$(id -g "$USER_NAME")
HOME_DIR=$(printf '%s\n' "$PW" | cut -d: -f6)
U_SHELL=$(printf '%s\n' "$PW" | cut -d: -f7)
IS_ROOT=0
if [ "$U_UID" -eq 0 ]; then
    [ "$USER_NAME" = root ] || die "$USER_NAME tem uid 0 sem ser root"
    IS_ROOT=1
fi
echo "bootstrap-console: conferindo a conta $USER_NAME (uid $U_UID)"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# --- conta ---
if [ "$IS_ROOT" -eq 0 ] && [ -f /etc/shadow ]; then
    PASS_FIELD=$(awk -F: -v u="$USER_NAME" '$1 == u { print $2 }' /etc/shadow)
    case "$PASS_FIELD" in
        "") ok "conta fora do /etc/shadow ou sem senha" ;;
        *[!!]*)
            case "$PASS_FIELD" in
                !*) warn "a senha de $USER_NAME esta travada (\"!\" no shadow): sem PAM o sshd recusa a chave. Destrave com 'passwd -u $USER_NAME' se for o caso" ;;
                *) ok "conta nao bloqueada" ;;
            esac ;;
        *)
            # So "!" (conta sem senha, bloqueada): troca por "*" (sem senha, mas login por chave liberado).
            U_RE=$(printf '%s' "$USER_NAME" | sed 's/[.]/\\./g')
            sed -i "s/^$U_RE:!\{1,\}:/$U_RE:*:/" /etc/shadow
            fixed "conta sem senha desbloqueada para login por chave (\"!\" -> \"*\" no shadow)" ;;
    esac
fi
case "$U_SHELL" in
    */nologin|*/false|"") warn "o shell de $USER_NAME e '${U_SHELL:-vazio}': o terminal nao abre. Troque com 'usermod -s /bin/bash $USER_NAME'" ;;
    *) ok "shell $U_SHELL" ;;
esac

# --- home, ~/.ssh e authorized_keys (StrictModes) ---
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || die "home de $USER_NAME ($HOME_DIR) nao existe"
SSH_DIR="$HOME_DIR/.ssh"
AK="$SSH_DIR/authorized_keys"
# Roda como root dentro de um diretorio do usuario: nao segue links.
[ ! -L "$SSH_DIR" ] || die "$SSH_DIR e um link simbolico; ajuste manualmente"
[ ! -L "$AK" ] || die "$AK e um link simbolico; ajuste manualmente"

perm_of() { ls -ldn "$1" | awk '{ print substr($1, 1, 10), $3, $4 }'; }
# Dono/modo esperados; so conta como ajuste se algo mudou.
ensure_perm() {
    before=$(perm_of "$1")
    chown "$U_UID:$U_GID" "$1"
    chmod "$2" "$1"
    if [ "$before" = "$(perm_of "$1")" ]; then ok "permissoes de $1"; else fixed "permissoes de $1 ($before -> $(perm_of "$1"))"; fi
}

case "$(ls -ld "$HOME_DIR" | cut -c6,9)" in
    *w*) chmod go-w "$HOME_DIR"; fixed "home $HOME_DIR sem escrita para grupo/outros (o sshd ignora a chave)" ;;
    *) ok "permissoes do home $HOME_DIR" ;;
esac
if [ ! -d "$SSH_DIR" ]; then
    mkdir "$SSH_DIR"
    fixed "criado $SSH_DIR"
fi
ensure_perm "$SSH_DIR" 700
if [ ! -f "$AK" ]; then
    : > "$AK"
    fixed "criado $AK"
fi
ensure_perm "$AK" 600

# --- chave do terminal ---
KEYBODY=$(printf '%s\n' "$PUBKEY" | awk '{ print $1 " " $2 }')
# none: ausente; good: presente sem opcoes que bloqueiem o terminal; bad: presente com no-pty/restrict/command=.
KEY_STATE=$(awk -v kb="$KEYBODY" '
    /^[[:space:]]*#/ { next }
    index($0, kb) {
        opts = tolower(substr($0, 1, index($0, kb) - 1))
        if (opts ~ /no-pty|restrict|command=/) bad = 1; else good = 1
    }
    END { print (bad ? "bad" : (good ? "good" : "none")) }' "$AK")
case "$KEY_STATE" in
    good) ok "chave do terminal no authorized_keys" ;;
    *)
        grep -vF "$KEYBODY" "$AK" > "$TMP_DIR/ak" || true
        printf '%s\n' "$PUBKEY" >> "$TMP_DIR/ak"
        cat "$TMP_DIR/ak" > "$AK"
        if [ "$KEY_STATE" = bad ]; then
            fixed "chave do terminal reescrita sem no-pty/restrict/command= (o terminal precisa de PTY)"
        else
            fixed "chave do terminal adicionada ao authorized_keys"
        fi ;;
esac

# --- sudo sem senha ---
# Roda uma linha de shell (fixa, deste script) como o usuario; root nao precisa de senha para isso.
as_user() {
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$USER_NAME" -- /bin/sh -c "$1" </dev/null >/dev/null 2>&1
    else
        su -s /bin/sh -c "$1" "$USER_NAME" </dev/null >/dev/null 2>&1
    fi
}
# -k ignora credenciais em cache: testa a regra, nao uma senha digitada ha pouco.
sudo_ok() { as_user 'sudo -n -k true'; }

if [ "$IS_ROOT" -eq 0 ]; then
    if ! command -v sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then
        ids=$( ( . /etc/os-release 2>/dev/null; echo "${ID:-} ${ID_LIKE:-}" ) || true )
        case " $ids " in
            *" debian "*|*" ubuntu "*) DEBIAN_FRONTEND=noninteractive apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q sudo ;;
            *" rhel "*|*" fedora "*|*" centos "*|*" almalinux "*|*" rocky "*) dnf -y install sudo ;;
            *" alpine "*) apk add --no-progress sudo ;;
            *) die "sudo ausente e distro nao suportada para instalar: $ids" ;;
        esac
        fixed "sudo instalado"
    fi

    CAN_TEST=1
    as_user 'true' || CAN_TEST=0
    if [ "$CAN_TEST" -eq 1 ] && sudo_ok; then
        ok "sudo sem senha"
    else
        [ "$CAN_TEST" -eq 1 ] || warn "nao consegui rodar comandos como $USER_NAME para testar o sudo; gravando a regra mesmo assim"
        mkdir -p /etc/sudoers.d
        chmod 755 /etc/sudoers.d
        SUDOERS_TMP=/etc/sudoers.d/.pve-patcher-console.tmp
        cat > "$SUDOERS_TMP" <<EOF
# Gerado pelo bootstrap-console.sh do pve-patcher (conta do Terminal SSH). Nao edite: rode o bootstrap de novo.
# "zz" no nome: lido por ultimo, para valer sobre regras com senha (no sudoers vale a ultima regra que casa).
Defaults:"$USER_NAME" !requiretty
"$USER_NAME" ALL=(ALL:ALL) NOPASSWD: ALL
EOF
        chmod 0440 "$SUDOERS_TMP"
        if ! visudo -cf "$SUDOERS_TMP" >/dev/null; then
            rm -f "$SUDOERS_TMP"
            die "sudoers invalido, abortado"
        fi
        mv "$SUDOERS_TMP" "$SUDOERS"
        # Alguns sudoers minimos (Alpine) nao incluem o diretorio.
        if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d' /etc/sudoers; then
            printf '@includedir /etc/sudoers.d\n' >> /etc/sudoers
            visudo -c >/dev/null || die "/etc/sudoers invalido apos incluir sudoers.d"
        fi
        if [ "$CAN_TEST" -eq 1 ]; then
            if ! sudo_ok; then
                sudo -l -U "$USER_NAME" >&2 || true
                die "gravei $SUDOERS mas o sudo de $USER_NAME ainda pede senha: alguma regra lida depois dele vence (veja acima)"
            fi
        elif ! sudo -l -U "$USER_NAME" | grep -q 'NOPASSWD: ALL'; then
            die "gravei $SUDOERS mas 'sudo -l -U $USER_NAME' nao mostra NOPASSWD: ALL"
        fi
        fixed "sudo sem senha ($SUDOERS)"
    fi
fi

# --- sshd (so avisos) ---
SSHD=$(command -v sshd 2>/dev/null || true)
if [ -z "$SSHD" ] && [ -x /usr/sbin/sshd ]; then SSHD=/usr/sbin/sshd; fi
if [ -z "$SSHD" ]; then
    warn "openssh-server nao encontrado; instale e habilite o sshd"
elif "$SSHD" -T -C "user=$USER_NAME,host=localhost,addr=127.0.0.1" > "$TMP_DIR/sshd" 2>/dev/null; then
    # Valor efetivo de uma opcao (o sshd -T repete a chave para listas: junta numa linha).
    cfg() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); out = out (out == "" ? "" : " ") $0 } END { print out }' "$TMP_DIR/sshd"; }
    [ "$(cfg pubkeyauthentication)" != no ] || warn "sshd com PubkeyAuthentication no"
    case "$(cfg authorizedkeysfile)" in
        *.ssh/authorized_keys*) ;;
        *) warn "sshd usa AuthorizedKeysFile '$(cfg authorizedkeysfile)', nao ~/.ssh/authorized_keys" ;;
    esac
    [ -z "$(cfg allowusers)" ] || warn "sshd com AllowUsers '$(cfg allowusers)': confira se inclui $USER_NAME"
    [ -z "$(cfg allowgroups)" ] || warn "sshd com AllowGroups '$(cfg allowgroups)': confira se inclui um grupo de $USER_NAME"
    if [ "$IS_ROOT" -eq 1 ]; then
        case "$(cfg permitrootlogin)" in
            no|forced-commands-only) warn "sshd com PermitRootLogin $(cfg permitrootlogin): root nao entra por chave" ;;
            *) ok "sshd permite login de root por chave" ;;
        esac
    fi
    ok "configuracao do sshd conferida"
else
    warn "nao consegui ler a configuracao efetiva do sshd (sshd -T); confira manualmente"
fi

echo "bootstrap-console: pronto. $USER_NAME: $ADJ ajuste(s), $WARN aviso(s)."
