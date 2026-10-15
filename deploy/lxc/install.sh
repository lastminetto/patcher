#!/bin/sh
# Instala o pve-patcher DENTRO do LXC (Debian 13), como root. Rodar a partir do tarball extraído:
#
#   tar xzf pve-patcher.tar.gz && sh deploy/lxc/install.sh [--skip-openbao]
#
# Ordem: (1) pacotes de runtime, (2) usuário/pastas, (3) binários, (4) unit systemd,
# (5) OpenBao (install-openbao.sh + init-openbao.sh, se existirem), (6) inicia o serviço.
#
# Decisões:
#  - Self-contained: não precisa do runtime .NET; precisa só de libssl, libstdc++ e zlib.
#  - InvariantGlobalization=true: dispensa o libicu (menos ~30 MB). Datas são formatadas à mão em pt-BR.
#  - tzdata é obrigatório: o fuso do agendador (America/Sao_Paulo) vem de /usr/share/zoneinfo.
set -eu

SKIP_BAO=0
[ "${1:-}" = "--skip-openbao" ] && SKIP_BAO=1

[ "$(id -u)" -eq 0 ] || { echo "Rode como root." >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
SRC="$ROOT/pve-patcher"
[ -f "$SRC/PvePatcher.Web" ] || { echo "Binários não encontrados em $SRC (rode a partir do tarball extraído)." >&2; exit 1; }

echo "==> Pacotes"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl tzdata libssl3t64 libstdc++6 zlib1g jq >/dev/null

echo "==> Usuário e pastas"
id pve-patcher >/dev/null 2>&1 || useradd --system --home-dir /var/lib/pve-patcher --shell /usr/sbin/nologin pve-patcher
install -d -m 0755 /opt/pve-patcher
install -d -m 0750 -o root -g pve-patcher /etc/pve-patcher
install -d -m 0750 -o pve-patcher -g pve-patcher /var/lib/pve-patcher

echo "==> Binários"
# Preserva a configuração; troca só os binários.
rm -rf /opt/pve-patcher.new && cp -a "$SRC" /opt/pve-patcher.new
chmod +x /opt/pve-patcher.new/PvePatcher.Web
systemctl stop pve-patcher 2>/dev/null || true
rm -rf /opt/pve-patcher.old
[ -d /opt/pve-patcher ] && mv /opt/pve-patcher /opt/pve-patcher.old
mv /opt/pve-patcher.new /opt/pve-patcher
rm -rf /opt/pve-patcher.old
chown -R root:root /opt/pve-patcher

if [ ! -f /etc/pve-patcher/appsettings.Production.json ]; then
  cat >/etc/pve-patcher/appsettings.Production.json <<'EOF'
{
  "Data": { "Path": "/var/lib/pve-patcher/state.db" },
  "Bootstrap": {
    "Clusters": [
      {
        "Id": "prod",
        "Name": "Produção",
        "Endpoints": [ "https://IP-DO-NO-PVE:8006" ],
        "CertFingerprintSha256": null
      }
    ]
  },
  "OpenBao": {
    "Address": "http://127.0.0.1:8200",
    "KvMount": "pve-patcher"
  }
}
EOF
  echo "    criado /etc/pve-patcher/appsettings.Production.json (EDITE: endpoints do cluster)"
fi
chown root:pve-patcher /etc/pve-patcher/appsettings.Production.json
chmod 0640 /etc/pve-patcher/appsettings.Production.json

echo "==> Serviço systemd"
install -m 0644 "$HERE/pve-patcher.service" /etc/systemd/system/pve-patcher.service
systemctl daemon-reload
systemctl enable pve-patcher >/dev/null

if [ "$SKIP_BAO" -eq 0 ]; then
  if [ -f "$ROOT/deploy/openbao/install-openbao.sh" ]; then
    echo "==> OpenBao (instalação)"
    bash "$ROOT/deploy/openbao/install-openbao.sh"
    if [ -f "$ROOT/deploy/openbao/init-openbao.sh" ]; then
      echo "==> OpenBao (init, unseal, AppRole). GUARDE as chaves de unseal que serão impressas."
      bash "$ROOT/deploy/openbao/init-openbao.sh"
    fi
    [ -f "$ROOT/deploy/openbao/unseal.sh" ] && install -m 0750 "$ROOT/deploy/openbao/unseal.sh" /usr/local/sbin/pve-patcher-unseal
  else
    echo "AVISO: deploy/openbao não encontrado no tarball; instale o OpenBao manualmente."
  fi
fi

echo "==> Iniciando"
systemctl restart pve-patcher
sleep 3
systemctl --no-pager --lines=5 status pve-patcher || true

cat <<EOF

Pronto. A UI responde em http://$(hostname -I | awk '{print $1}'):8080
Próximos passos:
  1. Edite /etc/pve-patcher/appsettings.Production.json (endpoints do cluster) e rode: systemctl restart pve-patcher
  2. Em cada cluster PVE:  deploy/proxmox/pve-role.sh  (imprime o token)
  3. Grave o token: na UI (Configurações > Clusters, após o login) ou com deploy/lxc/set-cluster-token.sh
  4. Em cada VM: adicione a chave pública (Configurações > Chave SSH) ao authorized_keys de uma conta root ou com sudo NOPASSWD
  5. Após cada reboot do LXC o cofre volta selado: rode o unseal (pve-patcher-unseal).
EOF
