#!/bin/sh
# Makes a private certificate authority and a server certificate for the relay.
#   ./make-certs.sh relay.home.lan 192.168.1.10
# Every argument is a name or IP address clients will use in PANDACODE_RELAY_URL (the first one
# is RELAY_HOST). Writes to ./certs:
#   fullchain.pem, privkey.pem   what Caddy serves (CERT_DIR)
#   ca.pem                       what each PandaCode computer trusts (PANDACODE_RELAY_CA)
#   ca-key.pem                   keep it private: it can mint certificates PandaCode would trust
# Run it again with the same certs/ folder to renew the server certificate under the same CA.
set -eu

[ "$#" -ge 1 ] || { echo "usage: $0 <name-or-ip> [<name-or-ip> ...]" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

dir="$(dirname "$0")/certs"
mkdir -p "$dir"
chmod 700 "$dir"
umask 077

if [ ! -f "$dir/ca.pem" ] || [ ! -f "$dir/ca-key.pem" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=PandaCode relay CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$dir/ca-key.pem" -out "$dir/ca.pem" 2>/dev/null
  echo "Made a new certificate authority: $dir/ca.pem"
fi

san=""
for host in "$@"; do
  case "$host" in
    *:*) kind=IP ;;           # IPv6
    *[!0-9.]*) kind=DNS ;;    # anything with a letter or dash
    *) kind=IP ;;             # dotted numbers
  esac
  san="${san:+$san,}$kind:$host"
done

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -subj "/CN=$1" -keyout "$dir/privkey.pem" -out "$dir/server.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$san" > "$dir/server.ext"
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca-key.pem" -CAcreateserial \
  -days 825 -extfile "$dir/server.ext" -out "$dir/server.pem" 2>/dev/null
cat "$dir/server.pem" "$dir/ca.pem" > "$dir/fullchain.pem"
rm -f "$dir/server.csr" "$dir/server.ext" "$dir/server.pem" "$dir/ca.srl"
chmod 644 "$dir/fullchain.pem" "$dir/ca.pem" "$dir/privkey.pem"
chmod 600 "$dir/ca-key.pem"

echo "Server certificate for $san, valid 825 days: $dir/fullchain.pem"
echo "Give each PandaCode computer $dir/ca.pem (PANDACODE_RELAY_CA, or relay-ca.pem in its app data folder)."
