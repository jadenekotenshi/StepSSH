#!/bin/sh
# Drive the real SSHSession against a throwaway local sshd.  Run: make session-smoke
ROOT=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/sess-smoke.XXXXXX")
PORT=${PORT:-22224}
cleanup() { [ -f "$T/sshd.pid" ] && kill "$(cat "$T/sshd.pid")" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
ssh-keygen -q -t ed25519 -N "" -f "$T/host"; ssh-keygen -q -t ed25519 -N "" -f "$T/user"
cp "$T/user.pub" "$T/authorized_keys"
cat > "$T/sshd_config" <<CFG
Port $PORT
ListenAddress 127.0.0.1
HostKey $T/host
PidFile $T/sshd.pid
AuthorizedKeysFile $T/authorized_keys
UsePAM no
PasswordAuthentication no
StrictModes no
Subsystem sftp /usr/libexec/sftp-server
CFG
/usr/sbin/sshd -f "$T/sshd_config" -E "$T/sshd.log" || { echo "could not start sshd"; exit 1; }
sleep 1
# pre-trust the host key so no modal alert can block the test
echo "[127.0.0.1]:$PORT $(cut -d' ' -f1,2 "$T/host.pub")" > "$T/known_hosts"
chmod 600 "$T/known_hosts"
# a hard timeout: a hung modal panel must not hang the test run
mkdir "$T/work"
"$ROOT/build/session_smoke" "$PORT" "$(id -un)" "$T/user" "$T/known_hosts" "$T/work" &
pid=$!
( sleep 90; kill $pid 2>/dev/null ) >/dev/null 2>&1 &
wd=$!
wait $pid; rc=$?
kill $wd >/dev/null 2>&1; wait $wd >/dev/null 2>&1
exit $rc
