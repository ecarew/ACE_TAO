#!/bin/sh
# Regenerates the Transport test's certificates and keys (TEST ONLY).
# The CA key is made in a temporary directory and discarded, so the CA
# cannot sign anything else.  Needs OpenSSL 3.4 or later (-not_before).
set -e
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
O=${OPENSSL:-openssl}
PASS=transport-test-pass
printf '%s' "$PASS" > password.txt

key () {  # NAME: encrypted P-256 key NAME_key_enc.pem
  $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -aes-256-cbc -pass "pass:$PASS" -out "$1_key_enc.pem"
}
ext () {  # SPIFFE-NAME [DNS/IP]: extensions file
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nsubjectAltName=URI:spiffe://ace-tao.test/%s%s\n' \
    "$1" "${2:+,$2}" > "$T/ext"
}
cert () {  # NAME CN SPIFFE [SAN] [not_before not_after]: NAME_cert.pem signed by the CA
  $O req -new -key "$1_key_enc.pem" -passin "pass:$PASS" -subj "/CN=$2" -out "$T/$1.csr"
  ext "$3" "$4"
  if [ -n "$5" ]; then
    $O x509 -req -in "$T/$1.csr" -CA ca.pem -CAkey "$T/ca.key" -CAcreateserial \
      -not_before "$5" -not_after "$6" -extfile "$T/ext" -out "$1_cert.pem"
  else
    $O x509 -req -in "$T/$1.csr" -CA ca.pem -CAkey "$T/ca.key" -CAcreateserial \
      -days 7300 -extfile "$T/ext" -out "$1_cert.pem"
  fi
}

$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$T/ca.key"
$O req -x509 -new -key "$T/ca.key" -subj "/CN=TAO Transport Test Root" -days 7300 \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out ca.pem

key server;  cert server  transport-server  server  "DNS:localhost,IP:127.0.0.1"
key client;  cert client  transport-client  client
key client2; cert client2 transport-client2 client2
cp client_key_enc.pem expired_key_enc.pem
cert expired transport-expired expired "" 20200101000000Z 20200201000000Z

# Untrusted: self-signed, not from the test CA.
key stranger
$O req -x509 -new -key stranger_key_enc.pem -passin "pass:$PASS" -subj "/CN=transport-stranger" \
  -days 7300 -out stranger_cert.pem

# Deny-list signers: the configured one and an impostor.
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass "pass:$PASS" -out signer_key_enc.pem
$O pkey -in signer_key_enc.pem -passin "pass:$PASS" -pubout -out signer_pub.pem
$O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass "pass:$PASS" -out impostor_key_enc.pem
chmod 600 ./*_key_enc.pem
rm -f ca.srl
$O x509 -in ca.pem -noout -fingerprint -sha256
