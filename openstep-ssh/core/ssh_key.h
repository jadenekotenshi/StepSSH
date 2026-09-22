#ifndef SSH_KEY_H
#define SSH_KEY_H
#include "ssh_types.h"
#include "wire.h"
#include "rsa.h"
#include "ecc.h"

#define SSH_KEY_NONE    0
#define SSH_KEY_ED25519 1
#define SSH_KEY_RSA     2
#define SSH_KEY_ECDSA   3

/* A private key.  RSA and ECDSA keep heap data: always release with ssh_key_wipe(), and never
 * copy the struct by value (two copies would free the same memory). */
typedef struct {
    int      type;
    u8       pk[32];               /* ed25519 public key */
    u8       sk[64];               /* ed25519 seed || public key */
    rsa_priv *rsa;                 /* RSA */
    int      curve;                /* ECDSA: EC_P256 / EC_P384 / EC_P521 */
    bn       ec_d;                 /* ECDSA private scalar */
    ec_point ec_q;                 /* ECDSA public point */
    char     comment[128];
} ssh_key;

/* Parse a private key file.  Understands the OpenSSH format ("BEGIN OPENSSH PRIVATE KEY") for
 * ed25519, RSA and ECDSA keys, and the older PEM formats: "BEGIN RSA PRIVATE KEY" (PKCS#1),
 * "BEGIN EC PRIVATE KEY" (SEC1) -- both optionally encrypted with AES-CBC -- and unencrypted
 * PKCS#8 ("BEGIN PRIVATE KEY").
 * Returns 0 on success, -1 if malformed/unsupported, -2 if the key is encrypted and no
 * passphrase was given, -3 if the passphrase is wrong.  Decrypting OpenSSH-format keys uses
 * bcrypt-pbkdf, which is deliberately slow.  *err always points at a static description. */
int  ssh_key_parse_private(const char *text, size_t len, const char *passphrase,
                           ssh_key *out, const char **err);
void ssh_key_wipe(ssh_key *k);
/* The key's own type name: "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", ... */
const char *ssh_key_algo_name(const ssh_key *k);
/* Which signature algorithm to use, given the server's advertised "server-sig-algs" (may be NULL).
 * For RSA this picks rsa-sha2-512, then rsa-sha2-256, else the legacy SHA-1 "ssh-rsa". */
const char *ssh_key_pick_sigalg(const ssh_key *k, const char *server_sig_algs);
/* SSH wire-format public key blob. */
int  ssh_key_public_blob(const ssh_key *k, sbuf *out);
/* Signature blob = string algorithm || string signature.  sigalg NULL = the key's default. */
int  ssh_key_sign(const ssh_key *k, const char *sigalg, const u8 *data, size_t len, sbuf *sigblob);

/* Check a server's signature over `msg` (the exchange hash).  `keyblob` is the host key,
 * `sigblob` the signature blob, `expect_alg` the algorithm that was negotiated.
 * Returns 0 if valid; otherwise -1 and *err describes why. */
int  ssh_hostkey_verify(const u8 *keyblob, size_t keylen, const u8 *sigblob, size_t siglen,
                        const char *expect_alg, const u8 *msg, size_t msglen, const char **err);
/* The type name at the start of a public key blob ("ssh-rsa" ...). 0 on success. */
int  ssh_blob_type(const u8 *blob, size_t len, char *out, size_t outsz);

/* ---- key generation and export (ed25519 only) ---- */
int  ssh_key_generate_ed25519(ssh_key *out, const char *comment);
/* Append an OpenSSH private-key file to `out`.  passphrase NULL or "" = unencrypted; otherwise
 * aes256-ctr with a bcrypt-pbkdf key of `rounds` (16 is OpenSSH's default). */
int  ssh_key_write_private(const ssh_key *k, const char *passphrase, unsigned rounds, sbuf *out);
/* Append "<type> AAAA... comment\n". */
int  ssh_key_write_public_line(const ssh_key *k, sbuf *out);

/* "SHA256:<base64, no padding>" of a public key blob, as OpenSSH prints it. */
int  ssh_fingerprint_sha256(const u8 *blob, size_t len, char *out, size_t outsz);

#endif
