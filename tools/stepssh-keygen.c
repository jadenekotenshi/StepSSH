/*
 * stepssh-keygen -- key generator, syntax-compatible with OpenSSH's `ssh-keygen` for the one key
 * type this engine can generate.
 *
 *   stepssh-keygen [-q] [-t ed25519] [-f output_keyfile] [-C comment] [-N new_passphrase]
 *
 * Only ed25519 generation is implemented (matching the StepSSH.app GUI's own "Generate Key..." --
 * see the README's "Not supported" list); -t with anything else is refused rather than silently
 * producing the wrong thing. This can still be used to inspect any key stepssh/stepscp can load
 * (RSA, ECDSA, ed25519, OpenSSH or PEM/PKCS#8) with -y/-l -- reading is far less restricted than
 * generating.
 *
 * With no -f, the output path is prompted for (default ~/.ssh/id_ed25519); with no -N and a
 * terminal to prompt on, the passphrase is prompted for twice (empty = no passphrase, matching
 * ssh-keygen); with neither a terminal nor -N, the passphrase defaults to empty rather than
 * hanging, for scripted use.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "../core/ssh_key.h"
#include "../core/rng.h"
#include "../core/oscompat.h"
#include "clicommon.h"

static int quiet;

static int write_file(const char *path, const u8 *p, size_t len, int mode)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    chmod(path, (mode_t)mode);
    if (len && fwrite(p, 1, len, f) != len) { fclose(f); return -1; }
    return fclose(f);
}

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Prompt for a passphrase twice and require they match, matching ssh-keygen's own flow; empty is
 * accepted immediately (no confirmation needed for "no passphrase"). Returns a static buffer, or
 * NULL after too many mismatches. */
static char *prompt_new_passphrase(void)
{
    static char first[256];
    int tries;
    for (tries = 0; tries < 3; tries++) {
        char *a = cli_read_secret("stepssh-keygen", "Enter passphrase (empty for no passphrase): ");
        char *b;
        if (!a) return NULL;
        strncpy(first, a, sizeof(first) - 1);
        first[sizeof(first) - 1] = '\0';
        if (first[0] == '\0') return first;
        b = cli_read_secret("stepssh-keygen", "Enter same passphrase again: ");
        if (b && strcmp(first, b) == 0) return first;
        fprintf(stderr, "stepssh-keygen: passphrases do not match. Try again.\n");
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *type = "ed25519", *outpath = NULL, *comment = NULL, *newpass = NULL;
    int opt, have_newpass = 0;
    ssh_key k;
    sbuf priv, pub, blob;
    char fp[96], pubpath[1200], defpath[1200], hostbuf[256], commentbuf[400];

    while ((opt = getopt(argc, argv, "qt:f:C:N:")) != -1) {
        switch (opt) {
        case 'q': quiet = 1; break;
        case 't': type = optarg; break;
        case 'f': outpath = optarg; break;
        case 'C': comment = optarg; break;
        case 'N': newpass = optarg; have_newpass = 1; break;
        default:
            fprintf(stderr, "usage: stepssh-keygen [-q] [-t ed25519] [-f output_keyfile] [-C comment] [-N new_passphrase]\n");
            return 1;
        }
    }
    if (strcmp(type, "ed25519") != 0) {
        fprintf(stderr, "stepssh-keygen: -t %s: key generation is only implemented for ed25519\n"
                        "stepssh-keygen: (stepssh -i and stepscp -i can still *use* rsa/ecdsa keys -- "
                        "generating them needs a real ssh-keygen)\n", type);
        return 1;
    }

    if (!outpath) {
        const char *home = getenv("HOME");
        char reply[1200];
        if (home) sprintf(defpath, "%s/.ssh/id_ed25519", home); else strcpy(defpath, "id_ed25519");
        if (isatty(0)) {
            fprintf(stderr, "Enter file in which to save the key (%s): ", defpath);
            fflush(stderr);
            if (fgets(reply, sizeof(reply), stdin)) {
                reply[strcspn(reply, "\r\n")] = '\0';
                outpath = reply[0] ? cli_xstrdup(reply) : defpath;
            } else {
                outpath = defpath;
            }
        } else {
            outpath = defpath;
        }
    }
    if (file_exists(outpath)) {
        char q[1300];
        sprintf(q, "%s already exists.\nOverwrite (y/n)? ", outpath);
        if (!cli_confirm(q)) { fprintf(stderr, "stepssh-keygen: not overwriting %s\n", outpath); return 1; }
    }

    if (!comment) {
        const char *user = cli_current_user();
        if (gethostname(hostbuf, sizeof(hostbuf)) != 0) strcpy(hostbuf, "localhost");
        sprintf(commentbuf, "%.190s@%.190s", user ? user : "user", hostbuf);
        comment = commentbuf;
    }

    if (!have_newpass) {
        if (isatty(0)) newpass = prompt_new_passphrase();
        else newpass = "";
        if (!newpass) { fprintf(stderr, "stepssh-keygen: aborted\n"); return 1; }
    }

    if (!ssh_rng_seed_system()) { fprintf(stderr, "stepssh-keygen: no system entropy\n"); return 1; }
    if (!quiet) fprintf(stderr, "Generating public/private ed25519 key pair.\n");
    if (ssh_key_generate_ed25519(&k, comment) != 0) { fprintf(stderr, "stepssh-keygen: key generation failed\n"); return 1; }

    sb_init(&priv); sb_init(&pub); sb_init(&blob);
    if (ssh_key_write_private(&k, newpass[0] ? newpass : NULL, 16, &priv) != 0
        || ssh_key_write_public_line(&k, &pub) != 0) {
        fprintf(stderr, "stepssh-keygen: could not serialise the key\n");
        return 1;
    }
    if (strlen(outpath) + 5 >= sizeof(pubpath)) { fprintf(stderr, "stepssh-keygen: path too long\n"); return 1; }
    sprintf(pubpath, "%s.pub", outpath);
    if (write_file(outpath, priv.p, priv.len, 0600) != 0 || write_file(pubpath, pub.p, pub.len, 0644) != 0) {
        fprintf(stderr, "stepssh-keygen: %s: %s\n", outpath, strerror(errno));
        return 1;
    }

    ssh_key_public_blob(&k, &blob);
    ssh_fingerprint_sha256(blob.p, blob.len, fp, sizeof(fp));
    if (!quiet) {
        fprintf(stderr, "Your identification has been saved in %s\n", outpath);
        fprintf(stderr, "Your public key has been saved in %s\n", pubpath);
        fprintf(stderr, "The key fingerprint is:\n");
    }
    printf("%s %s (ED25519)\n", fp, comment);
    return 0;
}
