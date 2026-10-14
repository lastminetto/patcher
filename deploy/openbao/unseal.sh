#!/usr/bin/env bash
# Desseala o OpenBao pedindo as chaves interativamente (sem eco, nada fica no histórico).
# Rode após cada reinício do LXC/serviço.
set -euo pipefail

export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
command -v bao >/dev/null || { echo "bao não instalado." >&2; exit 1; }

sealed() { bao status -format=json 2>/dev/null | grep -q '"sealed": *true'; }

sealed || { echo "O cofre já está aberto (ou inacessível: bao status)."; exit 0; }

while sealed; do
  read -rsp "Chave de unseal: " KEY
  echo
  [ -n "$KEY" ] || continue
  bao operator unseal "$KEY" | grep -E 'Sealed|Unseal Progress' || true
  unset KEY
done
echo "Cofre aberto."
