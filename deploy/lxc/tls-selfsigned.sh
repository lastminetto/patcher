#!/bin/sh
# Gera o certificado TLS autoassinado do pve-patcher (o Kestrel serve HTTPS na 8443). Roda como root no LXC.
#
#   sh deploy/lxc/tls-selfsigned.sh            # cria se ainda não existir
#   sh deploy/lxc/tls-selfsigned.sh --force    # renova (depois: systemctl restart pve-patcher)
#
# Chave ECDSA P-256, validade de 10 anos, SAN com hostname, FQDN, localhost e todos os IPs do LXC.
# Para usar um certificado próprio, substitua cert.pem/key.pem (PEM) no mesmo diretório e reinicie o serviço.
# Renovar troca o pin do comando de bootstrap das VMs (a tela de Configurações mostra o novo).
set -eu

DIR=/etc/pve-patcher/tls
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

die() { echo "tls: $1" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "rode como root"
command -v openssl >/dev/null 2>&1 || die "openssl não instalado (apt-get install openssl)"
getent group pve-patcher >/dev/null 2>&1 || die "grupo pve-patcher não existe (rode o install.sh)"

show() {
    echo "tls: certificado em $DIR/cert.pem"
    openssl x509 -in "$DIR/cert.pem" -noout -subject -enddate -fingerprint -sha256 | sed 's/^/tls:   /'
    pin=$(openssl x509 -in "$DIR/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)
    echo "tls:   pin do bootstrap: sha256//$pin"
}

if [ "$FORCE" -eq 0 ] && [ -f "$DIR/cert.pem" ] && [ -f "$DIR/key.pem" ]; then
    show
    exit 0
fi

install -d -m 0750 -o root -g pve-patcher "$DIR"

HOST=$(hostname)
FQDN=$(hostname -f 2>/dev/null || echo "$HOST")
SAN="DNS:$HOST,DNS:localhost,IP:127.0.0.1"
[ "$FQDN" = "$HOST" ] || SAN="DNS:$FQDN,$SAN"
for ip in $(hostname -I 2>/dev/null); do
    case "$ip" in
        127.0.0.1) ;;
        *) SAN="$SAN,IP:$ip" ;;
    esac
done

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=$FQDN/O=pve-patcher" \
    -addext "subjectAltName=$SAN" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null || die "openssl req falhou"

install -m 0640 -o root -g pve-patcher "$TMP/key.pem" "$DIR/key.pem"
install -m 0644 -o root -g pve-patcher "$TMP/cert.pem" "$DIR/cert.pem"
echo "tls: gerado (SAN: $SAN)"
show
