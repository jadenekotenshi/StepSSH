#!/bin/sh
# Regenerate tests/keys/* with the host's real ssh-keygen (only needed if fixtures are lost;
# committed fixtures are what the tests use).  Passphrase for every "_enc" key: correct horse
cd "$(dirname "$0")/../tests/keys" || exit 1
PW="correct horse"
mk() {     # name type bits [extra ssh-keygen args...]
    name=$1; type=$2; bits=$3; shift 3
    ssh-keygen -q "$@" -t "$type" -b "$bits" -f "$name" -C "$name" || echo "FAILED: $name" >&2
}
for k in "rsa2048 rsa 2048" "rsa3072 rsa 3072" "ec256 ecdsa 256" "ec384 ecdsa 384" "ec521 ecdsa 521"; do
    set -- $k
    mk "$1_ssh"     "$2" "$3" -N ""
    mk "$1_ssh_enc" "$2" "$3" -N "$PW" -a 6 -Z aes256-ctr
done
for k in "rsa2048 rsa 2048" "ec256 ecdsa 256" "ec521 ecdsa 521"; do
    set -- $k
    mk "$1_pem"     "$2" "$3" -N "" -m PEM
    mk "$1_pem_enc" "$2" "$3" -N "$PW" -m PEM
done
mk rsa2048_pkcs8     rsa   2048 -N ""    -m PKCS8
mk ec384_pkcs8       ecdsa 384  -N ""    -m PKCS8
mk rsa2048_pkcs8_enc rsa   2048 -N "$PW" -m PKCS8

# Named-curve encodings (what OpenSSL 1.1+/3 writes); LibreSSL's ssh-keygen above writes explicit parameters.
openssl ecparam -name prime256v1 -genkey -noout -out ec256_pem_named 2>/dev/null
ssh-keygen -y -f ec256_pem_named > ec256_pem_named.pub
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out ec384_pkcs8_named 2>/dev/null
ssh-keygen -y -f ec384_pkcs8_named > ec384_pkcs8_named.pub
openssl ecparam -name secp521r1 -genkey -noout -out ec521_pem_named 2>/dev/null
ssh-keygen -y -f ec521_pem_named > ec521_pem_named.pub
