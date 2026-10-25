#!/bin/bash
# Create (or renew) the self-signed HTTPS certificate in tls/.
# Meets Apple's rules for TLS server certificates (iOS 13+): RSA 2048, SHA-256,
# at most 825 days valid, subjectAltName and extendedKeyUsage=serverAuth.
#
# Usage: ./make_cert.sh [--force] [extra-host-or-ip ...]
#   The machine's own IP addresses are included automatically. Add your public IP or
#   DNS name if you open the page from the internet, e.g. ./make_cert.sh --force 203.0.113.7
#   Without --force it only renews when the certificate expires within 30 days.
cd "$(dirname "$0")" || exit 1
FORCE=0
[ "$1" = "--force" ] && { FORCE=1; shift; }
EXTRA=("$@")
[ -f tls/extra_hosts ] && [ ${#EXTRA[@]} -eq 0 ] && read -r -a EXTRA < tls/extra_hosts

mkdir -p tls && chmod 700 tls
if [ "$FORCE" = 0 ] && [ -f tls/cert.pem ] \
   && openssl x509 -in tls/cert.pem -noout -checkend 2592000 >/dev/null 2>&1; then
    exit 0
fi
SANS="DNS:localhost,IP:127.0.0.1,DNS:$(hostname)"
for ip in $(hostname -I 2>/dev/null); do
    case "$ip" in *:*) ;; *) SANS="$SANS,IP:$ip" ;; esac
done
for h in "${EXTRA[@]}"; do
    if [[ "$h" =~ ^[0-9.]+$ ]]; then SANS="$SANS,IP:$h"; else SANS="$SANS,DNS:$h"; fi
done
[ ${#EXTRA[@]} -gt 0 ] && echo "${EXTRA[*]}" > tls/extra_hosts
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 820 \
    -subj "/CN=celldrift" \
    -addext "subjectAltName=$SANS" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -keyout tls/key.pem.new -out tls/cert.pem.new 2>/dev/null || { echo "creating the certificate failed"; exit 1; }
mv -f tls/key.pem.new tls/key.pem
mv -f tls/cert.pem.new tls/cert.pem
chmod 600 tls/key.pem
echo "new certificate for $SANS, $(openssl x509 -in tls/cert.pem -noout -enddate)"
