#!/usr/bin/env bash
# Cria o LXC do pve-patcher (Debian 13, unprivileged). Rodar como root em um nó do Proxmox.
#
#   ./create-lxc.sh --vmid 150 --hostname pve-patcher --bridge vmbr0 --vlan 20 \
#                   --ip 172.22.20.50/24 --gw 172.22.20.1 --storage local-lvm \
#                   [--template local:vztmpl/debian-13-standard_13.0-1_amd64.tar.zst] \
#                   [--template-storage local] [--nameserver 172.22.20.1] [--password-file ARQ]
#
# 1 vCPU, 1024 MB, 8 GB, onboot=1, nesting desligado. Cria, inicia e imprime os próximos passos.
set -euo pipefail

VMID=""; HOSTNAME_="pve-patcher"; BRIDGE="vmbr0"; VLAN=""; IP=""; GW=""; STORAGE=""
TEMPLATE=""; TPL_STORAGE="local"; NAMESERVER=""; PWFILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --vmid) VMID="${2:?}"; shift 2 ;;
    --hostname) HOSTNAME_="${2:?}"; shift 2 ;;
    --bridge) BRIDGE="${2:?}"; shift 2 ;;
    --vlan) VLAN="${2:?}"; shift 2 ;;
    --ip) IP="${2:?}"; shift 2 ;;
    --gw) GW="${2:?}"; shift 2 ;;
    --storage) STORAGE="${2:?}"; shift 2 ;;
    --template) TEMPLATE="${2:?}"; shift 2 ;;
    --template-storage) TPL_STORAGE="${2:?}"; shift 2 ;;
    --nameserver) NAMESERVER="${2:?}"; shift 2 ;;
    --password-file) PWFILE="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Opção desconhecida: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Rode como root em um nó do Proxmox." >&2; exit 1; }
command -v pct >/dev/null || { echo "pct não encontrado: rode no nó do PVE." >&2; exit 1; }
for v in VMID IP GW STORAGE; do [ -n "${!v}" ] || { echo "Falta --${v,,}" >&2; exit 2; }; done
[[ "$IP" == */* ]] || { echo "--ip precisa estar em CIDR (ex.: 172.22.20.50/24)" >&2; exit 2; }
pct status "$VMID" >/dev/null 2>&1 && { echo "VMID $VMID já existe." >&2; exit 1; }

if [ -z "$TEMPLATE" ]; then
  # Procura o template Debian 13 já baixado; senão baixa o mais recente do pveam.
  TEMPLATE="$(pveam list "$TPL_STORAGE" 2>/dev/null | awk '/debian-13-standard/ {print $1}' | sort -V | tail -n1 || true)"
  if [ -z "$TEMPLATE" ]; then
    echo "Template Debian 13 ausente em '$TPL_STORAGE'; baixando..."
    pveam update >/dev/null
    NAME="$(pveam available --section system | awk '/debian-13-standard/ {print $2}' | sort -V | tail -n1)"
    [ -n "$NAME" ] || { echo "pveam não lista debian-13-standard." >&2; exit 1; }
    pveam download "$TPL_STORAGE" "$NAME"
    TEMPLATE="${TPL_STORAGE}:vztmpl/${NAME}"
  fi
fi
echo "Template: $TEMPLATE"

NET="name=eth0,bridge=${BRIDGE},ip=${IP},gw=${GW}"
[ -n "$VLAN" ] && NET="${NET},tag=${VLAN}"

ARGS=(--hostname "$HOSTNAME_" --unprivileged 1 --cores 1 --memory 1024 --swap 0
      --rootfs "${STORAGE}:8" --net0 "$NET" --onboot 1 --features nesting=0
      --ostype debian --description "pve-patcher (UI de atualizações)")
[ -n "$NAMESERVER" ] && ARGS+=(--nameserver "$NAMESERVER")

if [ -n "$PWFILE" ]; then
  ARGS+=(--password "$(head -n1 "$PWFILE")")
else
  echo "Sem --password-file: o login por console ficará sem senha; entre com 'pct enter $VMID'."
fi

pct create "$VMID" "$TEMPLATE" "${ARGS[@]}"
pct start "$VMID"
sleep 5

cat <<EOF

LXC $VMID criado e iniciado (${IP%/*}).
Próximos passos:
  1. No Windows:  .\\publish.ps1   (gera publish/pve-patcher.tar.gz)
  2. scp publish/pve-patcher.tar.gz root@${IP%/*}:/root/   (habilite o sshd no LXC, ou use 'pct push $VMID')
  3. Dentro do LXC:  tar xzf pve-patcher.tar.gz && sh deploy/lxc/install.sh
Veja o README.md para a ordem completa.
EOF
