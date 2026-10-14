#!/usr/bin/env bash
# Prepara um cluster Proxmox para o pve-patcher. Rodar como root em UM nó do cluster (a config é do cluster inteiro).
#
#   ./pve-role.sh            cria/atualiza role, usuário, token e ACL; mostra o token só se ele for criado agora
#   ./pve-role.sh --rotate   remove e recria o token (o segredo antigo deixa de valer)
#
# Privilégios da role PvePatcher (somente leitura + snapshot):
#   Sys.Audit      listar nós/recursos do cluster (PVE 9: também cobre o monitor HMP)
#   VM.Audit       ler a configuração das VMs
#   VM.Snapshot    criar/apagar snapshots (snapshot sem vmstate não exige mais nada)
#   PVE 8: VM.Monitor            -> comandos do guest agent (network-get-interfaces, get-osinfo, ping)
#   PVE 9: VM.GuestAgent.Audit   -> o VM.Monitor foi removido no PVE 9 e dividido em VM.GuestAgent.*
#
# Token com privsep=1: as permissões efetivas do token são a INTERSECÇÃO do usuário com as ACLs do token.
# Por isso a ACL é dada aos dois, e um vazamento do token nunca vai além da role (nem se alguém
# ampliar o usuário depois). Com privsep=0 o token herdaria tudo do usuário.
set -euo pipefail

ROLE="PvePatcher"
PVE_USER="pve-patcher@pve"
TOKEN_NAME="svc"
TOKEN_ID="${PVE_USER}!${TOKEN_NAME}"
ROTATE=0

for arg in "$@"; do
  case "$arg" in
    --rotate) ROTATE=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "Opção desconhecida: $arg" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Rode como root num nó do PVE." >&2; exit 1; }
command -v pveum >/dev/null || { echo "pveum não encontrado: este não é um nó Proxmox." >&2; exit 1; }

# pveversion: "pve-manager/9.0.3/abcdef (running kernel: ...)"
PVE_MAJOR="$(pveversion | sed -n 's|^pve-manager/\([0-9]\+\)\..*|\1|p')"
[ -n "$PVE_MAJOR" ] || { echo "Não consegui detectar a versão do PVE (pveversion)." >&2; exit 1; }

if [ "$PVE_MAJOR" -ge 9 ]; then
  AGENT_PRIV="VM.GuestAgent.Audit"
else
  AGENT_PRIV="VM.Monitor"
fi
PRIVS="Sys.Audit,VM.Audit,VM.Snapshot,${AGENT_PRIV}"
echo "PVE ${PVE_MAJOR}.x detectado; privilégios: ${PRIVS}"

# Role: cria ou atualiza (idempotente; também corrige uma role criada numa versão anterior).
if pveum role list --output-format json | grep -q "\"roleid\" *: *\"${ROLE}\""; then
  pveum role modify "$ROLE" --privs "$PRIVS" --append 0
  echo "Role ${ROLE} atualizada."
else
  pveum role add "$ROLE" --privs "$PRIVS"
  echo "Role ${ROLE} criada."
fi

# Usuário no realm pve (sem senha: só o token entra).
if pveum user list --output-format json | grep -q "\"userid\" *: *\"${PVE_USER}\""; then
  echo "Usuário ${PVE_USER} já existe."
else
  pveum user add "$PVE_USER" --comment "pve-patcher (servico)"
  echo "Usuário ${PVE_USER} criado."
fi

# Token
token_exists() {
  pveum user token list "$PVE_USER" --output-format json | grep -q "\"tokenid\" *: *\"${TOKEN_NAME}\""
}

CREATE_TOKEN=1
if token_exists; then
  if [ "$ROTATE" -eq 1 ]; then
    pveum user token remove "$PVE_USER" "$TOKEN_NAME"
    echo "Token antigo removido."
  else
    CREATE_TOKEN=0
    echo "Token ${TOKEN_ID} já existe. O segredo só é mostrado na criação;"
    echo "se foi perdido, rode novamente com --rotate (e atualize o cofre)."
  fi
fi

TOKEN_SECRET=""
if [ "$CREATE_TOKEN" -eq 1 ]; then
  OUT="$(pveum user token add "$PVE_USER" "$TOKEN_NAME" --privsep 1 --comment "pve-patcher" --output-format json)"
  TOKEN_SECRET="$(printf '%s' "$OUT" | sed -n 's/.*"value" *: *"\([^"]*\)".*/\1/p')"
  [ -n "$TOKEN_SECRET" ] || { echo "Falha ao ler o segredo do token." >&2; exit 1; }
fi

# ACL em / com propagação, para o usuário e para o token (privsep=1).
pveum acl modify / --roles "$ROLE" --users "$PVE_USER" --propagate 1
pveum acl modify / --roles "$ROLE" --tokens "$TOKEN_ID" --propagate 1
echo "ACL aplicada em / para ${PVE_USER} e ${TOKEN_ID}."

# Impressão digital do certificado do pveproxy (a que o pve-patcher valida).
CERT=/etc/pve/local/pveproxy-ssl.pem
[ -f "$CERT" ] || CERT=/etc/pve/local/pve-ssl.pem
FP="$(openssl x509 -noout -fingerprint -sha256 -in "$CERT" | cut -d= -f2)"

echo
echo "================ Cadastre no pve-patcher ================"
echo "token_id          : ${TOKEN_ID}"
if [ "$CREATE_TOKEN" -eq 1 ]; then
  echo "token_secret      : ${TOKEN_SECRET}"
  echo "                    (mostrado UMA vez; guarde no cofre agora)"
else
  echo "token_secret      : (não alterado)"
fi
echo "cert sha256       : ${FP}"
echo "certificado lido de ${CERT}"
echo "Esta impressão vale para ESTE nó; se os nós usam certificados diferentes,"
echo "rode 'openssl x509 -noout -fingerprint -sha256 -in ${CERT}' em cada um"
echo "(ou use um certificado de CA comum e deixe a impressão em branco)."
echo "========================================================="
