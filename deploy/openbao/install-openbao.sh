#!/usr/bin/env bash
# Instala o OpenBao num Debian 13 (LXC) a partir do .deb oficial dos releases do GitHub,
# verificando o SHA-256 contra o checksums.txt do mesmo release.
#
#   ./install-openbao.sh [--version 2.7.1]
#
# Depois: ./init-openbao.sh
set -euo pipefail

VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?falta o valor de --version}"; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Opção desconhecida: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Rode como root." >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates jq

case "$(dpkg --print-architecture)" in
  amd64) ARCH=amd64 ;;
  arm64) ARCH=arm64 ;;
  *) echo "Arquitetura sem .deb oficial: $(dpkg --print-architecture)" >&2; exit 1 ;;
esac

if [ -z "$VERSION" ]; then
  # /releases/latest redireciona para .../tag/vX.Y.Z
  VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/openbao/openbao/releases/latest | sed 's|.*/tag/v||')"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Versão inválida: '$VERSION'" >&2; exit 1; }

DEB="openbao_${VERSION}_linux_${ARCH}.deb"
BASE="https://github.com/openbao/openbao/releases/download/v${VERSION}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Baixando OpenBao ${VERSION} (${ARCH})..."
curl -fsSL -o "$TMP/$DEB" "$BASE/$DEB"
curl -fsSL -o "$TMP/checksums.txt" "$BASE/checksums.txt"

echo "Verificando checksum..."
(cd "$TMP" && grep " ${DEB}\$" checksums.txt | sha256sum -c -) \
  || { echo "Checksum NÃO confere; abortando." >&2; exit 1; }
# Assinaturas (cosign/gpg) também são publicadas (checksums.txt.sigstore.json / .gpgsig);
# a verificação delas é opcional e não é feita aqui.

apt-get install -y -qq "$TMP/$DEB"
command -v bao >/dev/null || { echo "Binário 'bao' não encontrado após instalar." >&2; exit 1; }

# Usuário/diretórios (o pacote normalmente cria o usuário; garantimos de qualquer forma).
getent passwd openbao >/dev/null || useradd --system --home-dir /var/lib/openbao --shell /usr/sbin/nologin openbao
install -d -m 0700 -o openbao -g openbao /var/lib/openbao
install -d -m 0755 /etc/openbao
install -m 0640 -o root -g openbao "$HERE/openbao.hcl" /etc/openbao/openbao.hcl
# Nossa unit tem precedência sobre a do pacote (/etc vence /usr/lib).
install -m 0644 "$HERE/openbao.service" /etc/systemd/system/openbao.service

systemctl daemon-reload
systemctl enable openbao >/dev/null
systemctl restart openbao
sleep 2
systemctl --no-pager --lines=0 status openbao || true

echo
echo "OpenBao ${VERSION} instalado e iniciado (selado). Próximo passo: ./init-openbao.sh"
