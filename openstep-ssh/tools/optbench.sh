#!/bin/sh
# Compare compiler optimisation flags for the crypto code on THIS machine (run on OPENSTEP).
#
#     sh tools/optbench.sh              # uses the default candidate list
#     sh tools/optbench.sh "-O" "-O2"   # or name your own, each as one argument
#
# For each candidate it deletes core/*.o and build/bench, rebuilds them with that OPT,
# runs the benchmark, and prints the key lines side by side.  Rebuilding the crypto
# code takes a while on an old machine; the benchmark itself takes a minute or so.
# Only the C core is rebuilt: the Objective-C app is not affected by these flags.
cd "$(dirname "$0")/.." || exit 1

if [ $# -gt 0 ]; then
    CANDIDATES=""
    for c in "$@"; do CANDIDATES="$CANDIDATES$c|"; done
else
    CANDIDATES="-O|-O2|-O -fomit-frame-pointer|-O2 -fomit-frame-pointer|-O2 -fno-schedule-insns -fno-schedule-insns2|"
fi

ROWS="curve25519: one public key|DH group14 (2048-bit)|ed25519: sign|ECDSA P-256: sign|RSA 2048: sign|bcrypt-pbkdf, 16 rounds|AES-256-CTR|ChaCha20-Poly1305|SHA-256"
OLDIFS=$IFS
echo "Optimisation flag comparison (lower ms/s is better; higher KB/s is better)"
echo

IFS='|'
for opt in $CANDIDATES; do
    IFS=$OLDIFS
    [ -z "$opt" ] && continue
    echo "=== OPT=$opt"
    rm -f core/*.o build/bench
    # MAKEARGS is empty on OPENSTEP; the development Mac sets it to "DEFS=" to test this script there
    if ! make -f Makefile.openstep build/bench OPT="$opt" $MAKEARGS >/dev/null 2>&1; then
        echo "    (this flag set did not build; skipped)"
        IFS='|'
        continue
    fi
    build/bench > build/bench.out 2>&1
    IFS='|'
    for row in $ROWS; do
        grep -F "$row" build/bench.out | sed 's/^  */    /'
    done
    IFS='|'
done
IFS=$OLDIFS
rm -f build/bench.out
echo
echo "To use the winner:  make -f Makefile.openstep clean; make -f Makefile.openstep OPT=\"<flags>\""
