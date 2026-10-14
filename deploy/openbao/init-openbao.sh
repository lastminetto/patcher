#!/usr/bin/env bash
# Inicializa o OpenBao do pve-patcher: init, unseal, KV v2, AppRole, policy e credenciais do serviço.
#
#   ./init-openbao.sh [--single-key] [--keep-root] [--service-user pve-patcher]
#
#   --single-key   1 chave / limiar 1 (padrão: 5 chaves, limiar 3). Mais cômodo, bem menos seguro.
#   --keep-root    não revoga o root token no fim (ele será impresso; trate como a chave do cofre).
#
# Se o cofre JÁ estiver inicializado, o init é pulado: desselar com ./unseal.sh e exportar BAO_TOKEN
# (um token com poder de administrar) antes de rodar este script para refazer as configurações.
set -euo pipefail

SINGLE=0
KEEP_ROOT=0
SVC_USER="pve-patcher"
while [ $# -gt 0 ]; do
  case "$1" in
    --single-key) SINGLE=1; shift ;;
    --keep-root) KEEP_ROOT=1; shift ;;
    --service-user) SVC_USER="${2:?falta o valor}"; shift 2 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "Opção desconhecida: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Rode como root." >&2; exit 1; }
command -v bao >/dev/null || { echo "bao não instalado (rode install-openbao.sh)." >&2; exit 1; }
command -v jq >/dev/null || { echo "jq não instalado (apt install jq)." >&2; exit 1; }

export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
MOUNT="pve-patcher"
APPROLE_DIR="/etc/pve-patcher/approle"

status_json() { bao status -format=json 2>/dev/null || true; }   # bao status sai com 2 quando selado
STATUS="$(status_json)"
[ -n "$STATUS" ] || { echo "Não consegui falar com o OpenBao em ${BAO_ADDR}." >&2; exit 1; }

if [ "$(jq -r .initialized <<<"$STATUS")" = "false" ]; then
  if [ "$SINGLE" -eq 1 ]; then SHARES=1; THRESHOLD=1; else SHARES=5; THRESHOLD=3; fi
  INIT="$(bao operator init -key-shares=$SHARES -key-threshold=$THRESHOLD -format=json)"
  BAO_TOKEN="$(jq -r .root_token <<<"$INIT")"
  export BAO_TOKEN

  echo
  echo "################  CHAVES DE UNSEAL - APARECEM SÓ AGORA  ################"
  jq -r '.unseal_keys_b64 | to_entries[] | "Chave \(.key + 1): \(.value)"' <<<"$INIT"
  echo "Limiar para abrir o cofre: ${THRESHOLD} de ${SHARES}."
  echo "Guarde FORA deste LXC (gerenciador de senhas, pessoas diferentes). Sem elas,"
  echo "os segredos são irrecuperáveis; com elas no mesmo disco, o cofre não protege nada."
  echo "#########################################################################"
  echo

  # Desseala usando as primeiras chaves até o limiar.
  for i in $(seq 0 $((THRESHOLD - 1))); do
    bao operator unseal "$(jq -r ".unseal_keys_b64[$i]" <<<"$INIT")" >/dev/null
  done
  unset INIT
else
  if [ "$(jq -r .sealed <<<"$STATUS")" = "true" ]; then
    echo "Cofre já inicializado, mas selado: rode ./unseal.sh e repita." >&2
    exit 1
  fi
  [ -n "${BAO_TOKEN:-}" ] || { echo "Cofre já inicializado: exporte BAO_TOKEN com um token administrativo." >&2; exit 1; }
fi

# KV v2
if bao secrets list -format=json | jq -e --arg m "${MOUNT}/" 'has($m)' >/dev/null; then
  echo "KV ${MOUNT}/ já habilitado."
else
  bao secrets enable -path="$MOUNT" -version=2 kv
fi

# AppRole
if bao auth list -format=json | jq -e 'has("approle/")' >/dev/null; then
  echo "AppRole já habilitado."
else
  bao auth enable approle
fi

# Policy (list é necessário só para inspeção manual; o app usa read/create/update/delete)
bao policy write pve-patcher - <<POLICY
path "${MOUNT}/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "${MOUNT}/metadata/*" {
  capabilities = ["read", "update", "delete", "list"]
}
POLICY

# Role: token de 1h (renovável até 24h); secret_id sem expiração e sem limite de usos.
bao write auth/approle/role/pve-patcher \
  token_policies=pve-patcher \
  token_ttl=1h token_max_ttl=24h \
  secret_id_ttl=0 secret_id_num_uses=0 \
  token_num_uses=0 >/dev/null

# Credenciais do serviço
getent passwd "$SVC_USER" >/dev/null \
  || useradd --system --home-dir "/var/lib/${SVC_USER}" --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$(dirname "$APPROLE_DIR")" "$APPROLE_DIR"

write_secret_file() {  # <arquivo> <valor>
  local f="$1"
  # Torna gravável só pelo root durante a troca; no fim: dono do serviço, 0400.
  [ -e "$f" ] && chmod 0600 "$f"
  (umask 077; printf '%s\n' "$2" > "$f")
  chown "$SVC_USER:$SVC_USER" "$f"
  chmod 0400 "$f"
}

write_secret_file "$APPROLE_DIR/role_id" "$(bao read -field=role_id auth/approle/role/pve-patcher/role-id)"
if [ -s "$APPROLE_DIR/secret_id" ] && [ -z "${ROTATE_SECRET_ID:-}" ]; then
  echo "secret_id já existe em $APPROLE_DIR (ROTATE_SECRET_ID=1 para gerar outro)."
else
  write_secret_file "$APPROLE_DIR/secret_id" "$(bao write -f -field=secret_id auth/approle/role/pve-patcher/secret-id)"
fi
echo "role_id/secret_id gravados em $APPROLE_DIR (dono ${SVC_USER}, 0400)."

if [ "$KEEP_ROOT" -eq 1 ]; then
  echo
  echo "Root token MANTIDO (--keep-root): ${BAO_TOKEN:-<o que você exportou>}"
  echo "Revogue depois com: BAO_TOKEN=... bao token revoke -self"
else
  bao token revoke -self >/dev/null
  echo "Root token revogado. Para administrar de novo: bao operator generate-root (usa as chaves de unseal)."
fi

echo
echo "Pronto. Configure no appsettings: OpenBao:Address=${BAO_ADDR}, OpenBao:KvMount=${MOUNT}."
