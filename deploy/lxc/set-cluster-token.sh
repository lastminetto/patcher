#!/usr/bin/env bash
# Grava o token de API de um cluster PVE no OpenBao (alternativa à tela Configurações > Clusters).
#
#   BAO_TOKEN=<token com escrita em pve-patcher/> ./set-cluster-token.sh <cluster-id> 'pve-patcher@pve!svc' <secret>
#
# Sem o <secret> na linha de comando, ele é lido do stdin (evita ir para o histórico do shell).
set -euo pipefail

ID="${1:?uso: $0 <cluster-id> <token_id> [token_secret]}"
TOKEN_ID="${2:?falta token_id (user@realm!nome)}"
if [ $# -ge 3 ]; then SECRET="$3"; else read -r -s -p "token_secret: " SECRET; echo; fi

export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
MOUNT="${BAO_MOUNT:-pve-patcher}"
: "${BAO_TOKEN:?exporte BAO_TOKEN (o root token, ou um token com escrita no mount)}"

bao kv put -mount="$MOUNT" "pve/clusters/$ID" token_id="$TOKEN_ID" token_secret="$SECRET" >/dev/null
echo "Token do cluster '$ID' gravado em $MOUNT/pve/clusters/$ID"
