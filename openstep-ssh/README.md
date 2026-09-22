# Secure Shell for OPENSTEP 4.2

A native SSH-2 client with a GUI terminal, an SFTP file browser and an in-app key generator,
written in C and Objective-C for OPENSTEP 4.2 (gcc 2.7.2, Foundation/AppKit). There is no
external `ssh` binary and no OpenSSL: the protocol and all cryptography are in this tree.

## What it does

| Feature | Detail |
|---|---|
| Terminal | VT100/xterm subset, 256 colours, scrollback, alternate screen (vi, less, tmux), copy/paste, function keys |
| Key exchange | curve25519-sha256, ecdh-sha2-nistp256/384/521, diffie-hellman-group-exchange-sha256, group16-sha512, group14-sha256, group14-sha1 (last resort) |
| Host keys | ssh-ed25519, ecdsa-sha2-nistp256/384/521, RSA (rsa-sha2-512, rsa-sha2-256, and legacy SHA-1 ssh-rsa) |
| Ciphers / MACs | chacha20-poly1305, aes256/128-ctr; hmac-sha2-256/512 (+etm); **legacy, chosen only if nothing better is offered:** aes256/128-cbc, hmac-sha1 (+etm) |
| Login | password, keyboard-interactive, public key: **ed25519, RSA, ECDSA**, plain or passphrase-protected; OpenSSH format and traditional PEM (PKCS#1, SEC1, PKCS#8) |
| Files | SFTP browser on a second channel of the same connection: list, upload, download (pipelined), new folder, rename, delete |
| Keys | *Connection > Generate Key...* creates an ed25519 key pair on this machine (optionally with a passphrase) |
| Safety | known_hosts checking (plain, wildcard, hashed), strict-KEX (Terrapin) mitigation, refuses to run on a weak RNG |

**Not supported:** compression, port forwarding, agent forwarding, X11, IPv6, mouse reporting,
recursive folder transfers, drag-and-drop, RSA/ECDSA key *generation* (ed25519 only), 3DES,
1024-bit diffie-hellman-group1-sha1, DSA keys, encrypted PKCS#8 keys (convert with
`ssh-keygen -p -m PEM -f KEY`).

## What was verified, and what was not

**Verified on the development Mac** (all also clean under AddressSanitizer + UBSan):

- `make test` &mdash; 1518 checks: crypto against independent references (Python, `openssl`, RFC
  vectors), big-integer arithmetic against Python's own integers, elliptic curves against OpenSSL
  signatures and ECDH secrets, RSA signatures **byte-identical** to OpenSSL's, every key type and file
  format that `ssh-keygen` produces, the SFTP engine against an in-memory fake server (short reads,
  fragmented delivery, injected failures, cancellation, connection loss, hostile input), and the
  terminal emulator including a fuzz test.
- `make interop` &mdash; 93 checks against a real OpenSSH 10.3 `sshd`: every cipher x MAC; every key
  exchange method; RSA/ECDSA/ed25519 login keys and host keys; encrypted keys; keys written by the
  app's own generator (read back by the real `ssh-keygen`); 3 MB and 20 MB transfers in both
  directions through **dozens of re-keys** (including Diffie-Hellman and CBC re-keys mid-transfer);
  SFTP against the real `sftp-server` (3000-entry directories, error cases, cancel-then-reuse).
- `make session-smoke` &mdash; the real Objective-C `SSHSession` and file browser run against `sshd`
  (modern AppKit, PostScript calls stubbed): login, PTY, output, resize, browser open/close/reopen,
  upload/download byte-for-byte.
- `make ui-smoke`, `make lint`, `make check-objc`.

**NOT verified on OPENSTEP itself** (only your machine can): text drawing through `PSshow`,
function-key codes, `NSTableView`/`NSScroller`/`NSSavePanel` behaviour, and the visual layout
of every panel. `make -f Makefile.openstep test` passing on your VM is what proves the C core on
gcc 2.7.2; everything in `app/` is checked only by the Mac-side smoke tests above.

Password login and the `keyboard-interactive` path were confirmed on a real host by the user.

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
make -f Makefile.openstep           # builds SecureShell.app
make -f Makefile.openstep bench     # how long RSA, bcrypt, Diffie-Hellman... take on this CPU
```

Expect `crypto: 843`, `vt: 223`, `sftp: 37`, `bignum: 239`, `ecc: 97`, `rsa: 79` &mdash; all "0 failed".
(If the machine has no `/dev/urandom`, the RNG test prints a note that it is crediting synthetic
entropy; that is expected.) `make` on OPENSTEP has no `mkdir -p`, so the makefile avoids it.

Run the app from a Terminal to see its startup messages (they begin `SecureShell:`):

```sh
./SecureShell.app/SecureShell
```

If a launch from Workspace does nothing but the Terminal launch works, the problem is the `.app`
folder layout, not the code.

### Things still worth watching on OPENSTEP (marked `[V]` in `app/Compat.h`)

- **`<AppKit/psops.h>`** &mdash; `PSshow`/`PSmoveto`, used to draw terminal text.
- **Function-key codes** `0xF700..0xF72D` in `-[NSEvent characters]`.
- `-[NSWindow setResizeIncrements:]` (guarded with `respondsToSelector:`).
- `NSScroller` part constants; `NSTableView -clickedRow` and `-selectedRowEnumerator`.
- `gethostbyname()` blocks the UI while resolving (use an IP address if slow).

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

## Layout

```
core/   SSH engine. Pure C89, no I/O: feed it bytes, drain its output and events.
  sha1 sha2 md5 hmac aes chacha nacl blowfish bcrypt   primitives
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
        TerminalView PromptPanel SecretField UIHelpers Compat.h main.m
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
  Diffie-Hellman) and the byte-oriented AES are not hardened against timing or cache attacks, and RSA
  signing is not blinded (it does verify its own result before releasing it, which defeats fault
  attacks). That is acceptable for a single-user client on an isolated retro machine; it would not be
  for a shared server. ChaCha20-Poly1305 and ed25519 are constant-time in their design.
- **ECDSA nonces** are hedged: derived from fresh randomness *and* the private key *and* the message.
- **Legacy algorithms** (CBC, hmac-sha1, SHA-1 signatures, group14-sha1) are offered last, so a server
  that supports anything better never negotiates them; the negotiation is integrity-protected by the
  exchange hash, so a network attacker cannot force a downgrade.
- Generated keys are written mode 0600 and an existing key file is never overwritten.

## Regenerating tables, vectors and fixtures (development Mac only)

```sh
python3 tools/gen_tables.py core       # SHA-2/MD5/AES/Blowfish/curve/DH constants, derived and verified
python3 tools/gen_nsenc.py             # NeXTSTEP encoding, from tools/NEXTSTEP.TXT
python3 tools/gen_vectors.py           # tests/vectors.h (independent reference implementations)
python3 tools/gen_bn_vectors.py        # big-integer vectors from Python's integers
python3 tools/gen_ec_vectors.py        # curve vectors from OpenSSL
python3 tools/gen_rsa_vectors.py       # RSA vectors from OpenSSL
sh      tools/gen_key_fixtures.sh      # tests/keys/ from the real ssh-keygen
```
