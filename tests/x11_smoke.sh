#!/bin/sh
# Drive the real SSHSession's X11 forwarding against a real local sshd (X11Forwarding yes) and
# two real Xvfb X servers.  Run: make x11-smoke
# Needs XQuartz (Xvfb, xauth, xdpyinfo at /opt/X11/bin) -- a separate target from session-smoke
# so that dependency stays optional.
ROOT=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/x11-smoke.XXXXXX")
PORT=${PORT:-22226}
AUTH_DISPLAY=97
OPEN_DISPLAY=98
AUTH_PORT=$((6000 + AUTH_DISPLAY))
OPEN_PORT=$((6000 + OPEN_DISPLAY))

for tool in /opt/X11/bin/Xvfb /opt/X11/bin/xauth /opt/X11/bin/xdpyinfo; do
    [ -x "$tool" ] || { echo "x11-smoke: $tool not found (needs XQuartz) -- skipping"; exit 0; }
done

cleanup() {
    [ -n "$XVPID_AUTH" ] && kill "$XVPID_AUTH" 2>/dev/null
    [ -n "$XVPID_OPEN" ] && kill "$XVPID_OPEN" 2>/dev/null
    [ -f "$T/sshd.pid" ] && kill "$(cat "$T/sshd.pid")" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N "" -f "$T/host"
ssh-keygen -q -t ed25519 -N "" -f "$T/user"
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
X11Forwarding yes
CFG
/usr/sbin/sshd -f "$T/sshd_config" -E "$T/sshd.log" || { echo "could not start sshd"; exit 1; }
sleep 1
echo "[127.0.0.1]:$PORT $(cut -d' ' -f1,2 "$T/host.pub")" > "$T/known_hosts"
chmod 600 "$T/known_hosts"

COOKIE=$(openssl rand -hex 16)
XAUTH_FILE="$T/xauth"
/opt/X11/bin/xauth -f "$XAUTH_FILE" add "127.0.0.1:$AUTH_DISPLAY" MIT-MAGIC-COOKIE-1 "$COOKIE" >/dev/null 2>&1
/opt/X11/bin/Xvfb ":$AUTH_DISPLAY" -listen tcp -nolisten local -auth "$XAUTH_FILE" -screen 0 800x600x8 \
    >"$T/xvfb_auth.log" 2>&1 &
XVPID_AUTH=$!
/opt/X11/bin/Xvfb ":$OPEN_DISPLAY" -listen tcp -nolisten local -screen 0 800x600x8 \
    >"$T/xvfb_open.log" 2>&1 &
XVPID_OPEN=$!
sleep 1

mkdir "$T/work"
"$ROOT/build/x11_smoke" "$PORT" "$(id -un)" "$T/user" "$T/known_hosts" "$COOKIE" "$AUTH_PORT" "$OPEN_PORT" &
pid=$!
( sleep 90; kill $pid 2>/dev/null ) >/dev/null 2>&1 &
wd=$!
wait $pid; rc=$?
kill $wd >/dev/null 2>&1; wait $wd >/dev/null 2>&1
exit $rc
