#!/usr/bin/env bash
# Desseala o OpenBao pedindo as chaves interativamente (sem eco, nada fica no histórico).
# Rode após cada reinício do LXC/serviço.
set -euo pipefail

export BAO_ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
command -v bao >/dev/null || { echo "bao não instalado." >&2; exit 1; }

# sealed | open | uninitialized | unreachable (bao status: 0 = aberto, 2 = selado, 1 = erro).
state() {
  local out rc=0
  out=$(bao status -format=json 2>/dev/null) || rc=$?
  if [ "$rc" -eq 1 ] || [ -z "$out" ]; then echo unreachable; return; fi
  if grep -q '"initialized": *false' <<<"$out"; then echo uninitialized; return; fi
  if grep -q '"sealed": *true' <<<"$out"; then echo sealed; else echo open; fi
}

case "$(state)" in
  open) echo "O cofre já está aberto ($BAO_ADDR)."; exit 0 ;;
  uninitialized) echo "O cofre não foi inicializado: rode deploy/openbao/init-openbao.sh." >&2; exit 1 ;;
  unreachable)
    echo "Cofre inacessível em $BAO_ADDR. Confira o serviço:" >&2
    echo "  systemctl status openbao --no-pager" >&2
    echo "  journalctl -u openbao -n 50 --no-pager" >&2
    exit 1 ;;
esac

while [ "$(state)" = sealed ]; do
  read -rsp "Chave de unseal: " KEY
  echo
  [ -n "$KEY" ] || continue
  bao operator unseal "$KEY" | grep -E 'Sealed|Unseal Progress' || true
  unset KEY
done

if [ "$(state)" = open ]; then
  echo "Cofre aberto."
else
  echo "O cofre ficou inacessível durante o unseal: confira journalctl -u openbao." >&2
  exit 1
fi
