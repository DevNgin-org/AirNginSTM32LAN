#!/bin/sh
set -eu
# Pass the src directory of the Arduino SSLClient dependency.
ssl=$(cd "${1:?pass SSLClient/src}" && pwd)
root=$(cd "$(dirname "$0")/.." && pwd)
w="$root/src/wire"
bear="$ssl/bearssl/src"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
cc -std=c11 -O2 -I"$ssl" -I"$w" -c "$w"/*.c \
    "$bear/symcipher/aes_ct.c" "$bear/symcipher/aes_ct_ctr.c" "$bear/symcipher/aes_ct_enc.c" \
    "$bear/aead/gcm.c" "$bear/hash/ghash_ctmul32.c" "$bear/codec/"*.c
ar rcs wire.a ./*.o
for name in crypto identity provision_query topic time; do
    cc -std=c11 -O2 -I"$w" "$root/tests/test_$name.c" wire.a -lm -o test
    ./test
done
c++ -std=c++14 -I"$root/src" "$root/tests/test_mobile.cpp" "$root/src/LanWire.cpp" "$root/src/LanDiscovery.cpp" wire.a -o test
./test
echo "Mobile discovery, profile and command contract passed"
