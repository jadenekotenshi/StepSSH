# StepSSH for OPENSTEP 4.2

A native SSH-2 client with a GUI terminal, an SFTP file browser and an in-app key generator,
written in C and Objective-C for OPENSTEP 4.2 (gcc 2.7.2, Foundation/AppKit). There is no
external `ssh` binary and no OpenSSL: the protocol and all cryptography are in this tree.

## What it does

| Feature | Detail |
|---|---|
| Terminal | VT100/xterm subset, 256 colours, scrollback, alternate screen (vi, less, tmux), copy/paste, function keys, mouse reporting (click and drag -- for vim, tmux and the like; not the wheel, see Mouse reporting below) |
| Key exchange | curve25519-sha256, ecdh-sha2-nistp256/384/521, diffie-hellman-group-exchange-sha256, group16-sha512, group14-sha256, group14-sha1 (last resort) |
| Host keys | ssh-ed25519, ecdsa-sha2-nistp256/384/521, RSA (rsa-sha2-512, rsa-sha2-256, and legacy SHA-1 ssh-rsa) |
| Ciphers / MACs | chacha20-poly1305, aes256/128-gcm, aes256/192/128-ctr; hmac-sha2-256/512 (+etm), hmac-sha1 (+etm); **legacy, chosen only if nothing better is offered:** aes256/192/128-cbc, blowfish-cbc, 3des-cbc, hmac-sha1-96, hmac-md5, hmac-md5-96 (+etm variants) |
| Login | password, keyboard-interactive, public key: **ed25519, RSA, ECDSA**, plain or passphrase-protected; OpenSSH format and traditional PEM (PKCS#1, SEC1, PKCS#8) |
| Files | SFTP browser on a second channel of the same connection: list, upload/download (pipelined, whole folders too), drag files/folders from Workspace's File Viewer onto the browser to upload, new folder, rename, delete |
| Keys | *Connection > Generate Key...* creates an ed25519 key pair on this machine (optionally with a passphrase) |
| Safety | known_hosts checking (plain, wildcard, hashed), strict-KEX (Terrapin) mitigation, refuses to run on a weak RNG |
| Forwarding | local port forwarding ("ssh -L"), any number of rules, managed from *Connection > Port Forwarding...* while connected |

**Not supported:** compression, *remote* port forwarding ("ssh -R") or dynamic/SOCKS forwarding ("ssh -D"
-- see Port forwarding below), agent forwarding, X11, IPv6, middle-click (mouse reporting
covers left/right and the wheel only -- see Mouse reporting below), dragging files *out* of the SFTP
browser to download (see Drag-and-drop below), recursive folder *deletion* (only individual files and
empty folders), RSA/ECDSA key
*generation* (ed25519 only), 1024-bit diffie-hellman-group1-sha1, DSA keys, encrypted PKCS#8
keys (convert with `ssh-keygen -p -m PEM -f KEY`).

## What was verified, and what was not

**Verified on the development Mac** (all also clean under AddressSanitizer + UBSan):

- `make test` &mdash; 1663 checks: crypto against independent references (Python, `openssl`, OpenSSL's
  own EVP API for AES-GCM, RFC/FIPS vectors), big-integer arithmetic against Python's own integers,
  elliptic curves against OpenSSL signatures and ECDH secrets, RSA signatures **byte-identical** to
  OpenSSL's, every key type and file format that `ssh-keygen` produces, the SFTP engine against an
  in-memory fake server (short reads, fragmented delivery, injected failures, cancellation, connection
  loss, hostile input), and the terminal emulator including a fuzz test.
- `make interop` &mdash; 112 checks against a real OpenSSH 10.3 `sshd`: every cipher x MAC; every key
  exchange method; RSA/ECDSA/ed25519 login keys and host keys; encrypted keys; keys written by the
  app's own generator (read back by the real `ssh-keygen`); 3 MB and 20 MB transfers in both
  directions through **dozens of re-keys** (including Diffie-Hellman and CBC re-keys mid-transfer);
  SFTP against the real `sftp-server` (3000-entry directories, error cases, cancel-then-reuse).
- `make session-smoke` &mdash; the real Objective-C `SSHSession` and file browser run against `sshd`
  (modern AppKit, PostScript calls stubbed): login, PTY, output, resize, browser open/close/reopen,
  upload/download byte-for-byte.
- `make ui-smoke`, `make lint`, `make check-objc`.

**Confirmed on OPENSTEP 4.2** (86Box, Pentium II/400, reported by the author): `make -f Makefile.openstep
test` passes and the app builds; it launches from Workspace Manager and `open`, with its icon; terminal text
renders; the New Connection panel lays out correctly; first-run entropy seeding works; password and
public-key logins work; key generation works; the file browser opens on a connection; `bench` timings are
reasonable on that CPU.

Also confirmed: copy and paste within the VM, and SFTP upload/download.

**Fixed, pending confirmation on OPENSTEP:** the arrow keys printed a literal `A`/`B`/`C`/`D` instead of
moving the cursor -- but only *in an editor's insert mode*; in `vi`'s command mode the arrows already worked.
That was the key clue: `vi`'s command mode has always had built-in recognition of the old VT52 cursor codes
(`ESC A`/`ESC B`/`ESC C`/`ESC D` -- no CSI bracket, predating ANSI terminals), while insert mode only
recognises the modern ANSI form (`ESC [ A`). A trace capture confirmed it: OPENSTEP delivers an arrow key
as **two separate keyDown events** -- a lone, unmodified `ESC` (`U+001B`, alone, nothing else in the same
event), then a separate keyDown for a lone, unmodified letter (`A`/`B`/`C`/`D` for up/down/right/left) --
never one event carrying a single codepoint, and never the bracket. `app/Compat.h`'s `NSUpArrowFunctionKey`-
style codepoints (0xF700...) are real AppKit constants, just apparently not what this OPENSTEP/86Box keyboard
setup actually sends.

`app/TerminalView.m` now holds a lone, unmodified ESC for 50&nbsp;ms (the same technique terminals and
readline use to tell "the start of a function-key sequence" from "someone pressed Escape") -- if one of
`A`/`B`/`C`/`D` follows, unmodified, within that window, it sends the correct VT100 sequence instead of the
raw pair; otherwise (a different key, a modified key, or nothing at all) the ESC is sent on its own and the
next key is handled normally, so a real Escape keypress (very common in `vi`) still works as before, just
delayed by up to 50&nbsp;ms -- well under typical SSH network latency. Covered by 8 new `ui-smoke` checks,
including the real timeout path (57 checks total, up from 49).

**Still needed:** the *other* special keys (Backspace, Tab, Home/End, Page Up/Down, F1-F12) were not part of
that trace and may have the same two-event problem with different candidate letters/digits following the
ESC -- or may not send ESC at all. Nothing has been changed for them yet; guessing their mapping without
data risks the same wrong-fix problem the arrows almost had. If any of them misbehave, run

```sh
touch ~/.StepSSH.trace
```

press the misbehaving key on its own a couple of times, and send the file -- a lone ESC entry followed by
knowing what character appeared in the remote editor is enough to extend the same fix to that key.
`NSHomeDirectory()`, `getenv("HOME")` and `NSUserName()` are also logged separately at startup now (see the
next paragraph).

**Second finding from that trace, unrelated to the arrow keys, now explained:** `cwd` and `HOME` were both `/`
when launched from Workspace Manager, which is also why the trace file turned up at `/.StepSSH.trace`
rather than inside a home directory. The author was testing logged in as `root`, whose account traditionally
has `/` as its home directory on Unix -- nothing to do with Workspace or this app. `NSHomeDirectory()`,
`getenv("HOME")` and `NSUserName()` stay logged at startup regardless, since they're cheap and worth having
if account setup ever changes.

**Also confirmed on OPENSTEP since:** recursive folder upload and download; dragging files/folders from
Workspace's File Viewer onto the SFTP browser to upload them (see Drag-and-drop below); local port
forwarding (see Port forwarding below); and mouse reporting in `vim` (see Mouse reporting below) -- the
last of the four features asked for after v0.0.2, now all confirmed.

**Not yet reported on OPENSTEP:** rename, delete, new folder, `NSSavePanel`/`NSOpenPanel` behaviour,
window resizing, and recovery from a dropped connection.

## Getting it into the VM

```sh
make dist          # -> dist/SSH.TAR  and  dist/SSH.ISO (a CD image containing SSH.TAR)
```

Attach `SSH.ISO` as a CD-ROM (or use any file transfer you have), then in OPENSTEP:

```sh
mkdir ~/ssh && cd ~/ssh
tar xf /Volumes/SSH/SSH.TAR
```

## Building on OPENSTEP

```sh
make -f Makefile.openstep test      # FIRST: the C core on the real compiler
make -f Makefile.openstep           # builds StepSSH.app
make -f Makefile.openstep bench     # how long RSA, bcrypt, Diffie-Hellman... take on this CPU
```

Expect `crypto: 843`, `vt: 223`, `sftp: 37`, `bignum: 239`, `ecc: 97`, `rsa: 79` &mdash; all "0 failed".
(If the machine has no `/dev/urandom`, the RNG test prints a note that it is crediting synthetic
entropy; that is expected.) `make` on OPENSTEP has no `mkdir -p`, so the makefile avoids it.

Run the app from a Terminal to see its startup messages (they begin `StepSSH:`):

```sh
./StepSSH.app/StepSSH
```

### Launching from Workspace

`StepSSH.app` is deliberately just a folder holding the executable: that is all NeXT's own
`Edit.app` has (apart from its language folders). What Workspace does *not* find in the folder is the
icon: NeXT links the application icon and file-type table into the executable, as a read-only
`__ICON` segment, using `app/StepSSH.iconheader` and `app/StepSSH.tiff`. `Makefile.openstep`
does the same (`-sectcreate __ICON ...`; if your `cc` rejects those flags it says so and links without
an icon). To see what was linked in:

```sh
make -f Makefile.openstep iconcheck      # expect: segname __ICON, sections __header and app
```

If double-clicking still does nothing, find out how far the launch got. Workspace throws away the
application's stderr, so the startup messages can also go to a file, which is used only if it exists:

```sh
touch ~/.StepSSH.trace               # then launch from Workspace
cat ~/.StepSSH.trace                 # argv, working directory, and each startup step reached
```

(`open` behaves like Workspace. `rm ~/.StepSSH.trace` turns tracing off again.)

### Things still worth watching on OPENSTEP (marked `[V]` in `app/Compat.h`)

- **`<AppKit/psops.h>`** &mdash; `PSshow`/`PSmoveto`, used to draw terminal text.
- **Function-key codes** `0xF700..0xF72D` in `-[NSEvent characters]` -- confirmed *not* how arrow keys are
  delivered on this setup (see the arrow-key writeup above); Insert/Delete/Home/End/Page Up/Down/F1-F12
  still use this and are unconfirmed.
- `-[NSWindow setResizeIncrements:]` (guarded with `respondsToSelector:`).
- `NSScroller` part constants; `NSTableView -clickedRow` and `-selectedRowEnumerator`.
- `gethostbyname()` blocks the UI while resolving (use an IP address if slow).
- `-[NSOpenPanel setCanChooseDirectories:]` (used so *Upload* can pick a folder to upload
  recursively): part of the OpenStep specification and present in GNUstep's from-scratch
  reimplementation of it, so it should be there, but is not yet confirmed on OPENSTEP 4.2 itself.
- **`opendir`/`readdir`/`closedir`/`DIR`** (walking a local folder for a recursive upload): on this
  OPENSTEP install, `<dirent.h>` is found but does not `typedef DIR`; `<sys/dir.h>`, the classic BSD
  header, does, but pairs it with `struct direct` (the pre-POSIX name) instead of `struct dirent` --
  `app/SFTPBrowser.m` picks the right one per platform. `struct direct.d_name` is assumed to be
  NUL-terminated, as `struct dirent.d_name` is; true of every implementation checked, but not
  independently confirmed for this one.

## Speed on an old CPU

Some operations are deliberately expensive and the window is unresponsive while they run. Run
`make -f Makefile.openstep bench` to see the real numbers. Expect, roughly and relative to the
cost of one curve25519 operation: ECDSA P-256 several times more, RSA-2048 signing and Diffie-Hellman
group14 a few times more still, RSA-4096 and DH group16 much more, and unlocking an ssh-keygen-default
passphrase key (bcrypt, 16 rounds) the slowest of all. Verifying an RSA host key is cheap. ChaCha20 is
preferred over AES for bulk data because it is faster on CPUs of that era.

### Choosing compiler flags

The default is `-O`. gcc 2.7.2's `-O2` is not always faster on the i386 (few registers, so extra
scheduling can cause spills), and on at least one machine `-O` measured faster. To test on yours:

```sh
sh tools/optbench.sh                                    # tries several flag sets, prints a comparison
make -f Makefile.openstep clean
make -f Makefile.openstep OPT="-O2 -fomit-frame-pointer"    # then build with the winner
```

Set `OPT`, not `CFLAGS`: overriding `CFLAGS` would drop `-DOPENSTEP` and the include paths.
Only the C core is sensitive to this; the Objective-C app is limited by the display and network.

## Port forwarding

**Confirmed working on OPENSTEP 4.2**, after two build fixes along the way (a missing `O_NONBLOCK`
fallback and an undeclared `fcntl()` prototype in the new file -- both already-known OPENSTEP quirks
this project had solved once before in `SSHSession.m`, just not carried over; see the commit history).

*Connection > Port Forwarding...*, available once connected, opens a small window listing this
connection's forwarding rules: a local port, and the host:port on the other side of the connection
that port relays to (`ssh -L localport:host:port`). *Add...* asks for the three, binds the local port
immediately (127.0.0.1 only -- a forward is never exposed to the rest of the network, the same default
OpenSSH itself uses without `GatewayPorts`), and starts relaying; *Remove* stops it and disconnects
anything using it. Any number of rules can be active together, and each one accepts any number of
simultaneous connections (e.g. several browser tabs through the same forwarded port) -- every one of
those becomes its own SSH channel (`direct-tcpip`, RFC 4254 s.7.2) on the same connection, alongside
the terminal and file browser's channels.

**Not implemented: remote forwarding (`ssh -R`) or dynamic/SOCKS forwarding (`ssh -D`).** Remote
forwarding would mean accepting a server-initiated channel open, which this client's connection layer
categorically refuses (every unsolicited `CHANNEL_OPEN` gets an "administratively prohibited" refusal,
on purpose: a client should not silently let a server open connections through it); dynamic forwarding
would mean implementing a small SOCKS4/5 server. Both are plausible future additions on top of the same
`direct-tcpip` machinery local forwarding already uses, just not attempted in this pass.

## Mouse reporting

**Confirmed working on OPENSTEP 4.2** (in `vim`), after a build fix (see below).

When the remote program asks for it (vim, tmux, htop, mc, and most full-screen terminal apps that use
the mouse), clicks and drags are sent to it instead of doing local text selection -- e.g. clicking to
move vim's cursor or resize a tmux pane. Hold **Shift** to bypass this and get ordinary local selection
regardless, the same override real xterm uses.

Supported: X10 (click only), normal (click and release), button-event and any-event tracking (also
drag motion, respectively only while a button is held or always), SGR extended coordinates (what
vim/tmux request by default; needed for terminals wider or taller than 223 cells), and focus-in/out
events. The left and right buttons are both reported; **the middle button is not** (`otherMouseDown:`
and friends were not confirmed as available on OPENSTEP 4.2's AppKit, unlike `rightMouseDown:`, which
has been part of NSResponder since NeXTSTEP). Highlight tracking (mode 1001) is deliberately not
implemented: it requires a cooperating program on the host, and xterm's own documentation warns that
getting it wrong can hang a real xterm.

**The scroll wheel is not reported, and does not scroll locally either, on OPENSTEP itself** (it works
on the development Mac, where this was first written and tested). `-[NSEvent deltaX]`/`deltaY` --
needed to read a wheel event's amount and direction at all -- turned out to be a genuine Mac OS X
addition, confirmed absent from OPENSTEP 4.2's real AppKit: not a mere undeclared-but-present method
like the `DIR`/`NSDragOperation` build breaks were, but explicitly gated "Mac OS X only" in GNUstep's
own from-scratch reimplementation of the OpenStep API, while the `NSScrollWheel` event type itself is
not gated. There is no confirmed way to read a wheel event's amount or direction on this platform, so
`-[TerminalView scrollWheel:]` does nothing there rather than guess at one. The scrollbar,
Shift-PageUp/PageDown, and click/drag mouse reporting are unaffected.

The wire encoding (`term/vt.c`'s `vt_encode_mouse`) was checked bit-for-bit against real xterm's own
source (`button.c`'s `BtnCode`/`EditorButton`), not just its written documentation -- one detail (which
code represents "no button" during any-event motion, and that SGR's release differs from the default
encoding's) is not spelled out in the xterm control-sequences document and was only caught this way.
36 unit tests in `tests/test_vt.c` and 12 UI-level tests in `tests/ui_smoke.m` cover it, all against
hand-computed expected bytes.

## Drag-and-drop

**Confirmed working on OPENSTEP 4.2**, after one build fix (see below).

Drag files or folders from Workspace's File Viewer onto the SFTP browser's file listing to upload them
into whatever directory it currently shows -- folders go through the same recursive upload as the
Upload panel. This uses `registerForDraggedTypes:` and the `NSDraggingDestination` informal protocol
on the table view, which are original OpenStep API present since NeXTSTEP; the drop is rejected (the
"no" cursor) while the browser isn't connected.

The drag-destination return type (`SFTPBrowser.m`'s `SFTPTableView`) needed a fix to build at all: the
type name `NSDragOperation` is not declared on this OPENSTEP install, even though the
`NSDragOperationNone`/`Copy` constants it returns are (plain integers, not typedef'd). `app/Compat.h`
now has `SSDragOp`, `unsigned int` under OPENSTEP and the real `NSDragOperation` on the host, used
instead of naming the type directly.

Dragging files *out* of the browser to download them is not implemented, and can't be done the way a
modern Cocoa app would: that relies on "promised" files (declare the drag immediately, supply the actual
bytes lazily once Workspace says where to put them -- `NSFilesPromisePboardType`,
`-namesOfPromisedFilesDroppedAtDestination:`), which is a Mac OS X 10.2 addition, confirmed absent from
OPENSTEP 4.2's AppKit (checked against GNUstep's headers, which gate it behind a Mac-OS-X-only version
check). The only OpenStep-era alternative -- the `NSPasteboardOwner` protocol's
`-pasteboard:provideDataForType:` -- supplies data synchronously when asked, which would mean blocking
the drag (and the whole app) until an SFTP download over the network finished; not worth doing for a
worse experience than the existing Download button and panel.

## Layout

```
core/   SSH engine. Pure C89, no I/O: feed it bytes, drain its output and events.
  sha1 sha2 md5 hmac aes gcm chacha nacl blowfish des bcrypt   primitives
  bignum ecc rsa                                       big integers, NIST curves, RSA PKCS#1
  rng                                                  entropy pool (see below)
  wire                                                 buffers, SSH wire format, base64
  ssh.c ssh_auth.c ssh_chan.c                          transport + key exchange, auth, channels
  ssh_key                                              key parsing (OpenSSH/PEM/PKCS#8), signing, host-key verification
  sftp                                                 SFTP v3 client: protocol, listing, pipelined transfers
  knownhosts oscompat
term/   vt.c (terminal emulator core), nsenc.c (NeXTSTEP <-> Unicode)
app/    Objective-C, all UI built in code (no nibs):
        AppController ConnectController KeyGenController SSHSession SFTPBrowser
        PortForward PortForwardController
        TerminalView PromptPanel SecretField UIHelpers Compat.h main.m
        StepSSH.iconheader, StepSSH.tiff   the application icon (linked in as __ICON)
tests/  unit tests, interop.sh, session/UI smoke tests, tests/keys/ (real ssh-keygen output)
tools/  table/vector generators, sshc (CLI SSH), sftpc (CLI SFTP), mkkey, bench, lint
```

The engines are *sans-I/O* on purpose: the same code is driven by a blocking `select()` loop in
`tools/sshc.c` on the Mac and by a 20 ms `NSTimer` poll in `app/SSHSession.m` on OPENSTEP.

## Security notes

- **Randomness.** OPENSTEP has no `/dev/urandom`. `core/rng.c` refuses to generate anything until 256
  bits of entropy have been *credited*, so a weak RNG fails closed. Sources: `/dev/urandom` if
  present, a seed file (`~/.ssh/random_seed`, mode 0600, replaced on every load), and mouse/keyboard
  timing (one bit per event, deliberately conservative). First run with no seed asks you to move the
  mouse until a bar fills.
- **Host keys** are checked against `~/.ssh/known_hosts`. Unknown hosts prompt with the SHA-256
  fingerprint; a *changed* key defaults to Cancel.
- **Passwords and passphrases** are never stored; they are typed into a custom field
  (`SecretField`) and wiped after use.
- **Not constant-time.** The big-integer code (RSA private operations, ECDSA scalar multiplication,
  Diffie-Hellman), the byte-oriented AES, and AES-GCM's GHASH (a bit-at-a-time GF(2^128) multiply)
  are not hardened against timing or cache attacks, and RSA signing is not blinded (it does verify
  its own result before releasing it, which defeats fault attacks). That is acceptable for a
  single-user client on an isolated retro machine; it would not be for a shared server.
  ChaCha20-Poly1305 and ed25519 are constant-time in their design.
- **ECDSA nonces** are hedged: derived from fresh randomness *and* the private key *and* the message.
- **Legacy algorithms** (CBC, blowfish-cbc, 3des-cbc, hmac-sha1, hmac-md5 and their truncated "-96"
  variants, SHA-1 signatures, group14-sha1) are offered last, so a server that supports anything
  better never negotiates them; the negotiation is integrity-protected by the exchange hash, so a
  network attacker cannot force a downgrade. They exist for interop with other software on old
  systems, not because they are recommended.
- **DES's tables are hand-transcribed, unlike every other fixed table in this codebase.**
  `tools/gen_tables.py` derives everything else from first principles (the AES S-box from GF(2^8)
  inversion, Blowfish's P/S-arrays from the digits of pi) specifically so nothing has to be typed
  from a published table. DES has no such derivation -- its permutations and S-boxes are arbitrary
  constants fixed by FIPS 46-3, the same for every DES implementation ever written. `core/des.c`
  documents how the transcription was checked: a standalone Python implementation verified against
  the FIPS 46-3 worked example, the DES weak-key fixed points, and `openssl enc -des-ede3-cbc`
  independently, with the C tables generated verbatim from that same verified data rather than
  retyped a second time.
- Generated keys are written mode 0600 and an existing key file is never overwritten.

## Regenerating tables, vectors and fixtures (development Mac only)

```sh
python3 tools/gen_tables.py core       # SHA-2/MD5/AES/Blowfish/curve/DH constants, derived and verified
python3 tools/gen_nsenc.py             # NeXTSTEP encoding, from tools/NEXTSTEP.TXT
python3 tools/gen_icon.py              # app/StepSSH.tiff, in the layout NeXT's Edit.app uses
python3 tools/gen_vectors.py           # tests/vectors.h (independent reference implementations;
                                        # AES-GCM vectors need libcrypto reachable via ctypes --
                                        # `openssl enc` has no usable AEAD/tag support to shell out to)
python3 tools/gen_bn_vectors.py        # big-integer vectors from Python's integers
python3 tools/gen_ec_vectors.py        # curve vectors from OpenSSL
python3 tools/gen_rsa_vectors.py       # RSA vectors from OpenSSL
sh      tools/gen_key_fixtures.sh      # tests/keys/ from the real ssh-keygen
```
