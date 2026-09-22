/*
 * mkkey -- write a new ed25519 key with the same code the app uses, for tests.
 *   mkkey <path> [passphrase] [comment]      writes <path> (0600) and <path>.pub
 * Prints the SHA-256 fingerprint.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../core/ssh_key.h"
#include "../core/rng.h"

static int write_file(const char *path, const sbuf *b, int mode)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    chmod(path, mode);
    fwrite(b->p, 1, b->len, f);
    return fclose(f);
}

int main(int argc, char **argv)
{
    ssh_key k;
    sbuf priv, pub, blob;
    char fp[64], pubpath[1024];
    if (argc < 2) { fprintf(stderr, "usage: mkkey path [passphrase] [comment]\n"); return 2; }
    if (!ssh_rng_seed_system()) { fprintf(stderr, "mkkey: no entropy\n"); return 2; }
    if (ssh_key_generate_ed25519(&k, argc > 3 ? argv[3] : "mkkey") != 0) return 2;
    sb_init(&priv); sb_init(&pub); sb_init(&blob);
    if (ssh_key_write_private(&k, argc > 2 ? argv[2] : NULL, 6, &priv) != 0) return 2;
    if (ssh_key_write_public_line(&k, &pub) != 0) return 2;
    strcpy(pubpath, argv[1]); strcat(pubpath, ".pub");
    if (write_file(argv[1], &priv, 0600) != 0 || write_file(pubpath, &pub, 0644) != 0) { perror("write"); return 2; }
    ssh_key_public_blob(&k, &blob);
    ssh_fingerprint_sha256(blob.p, blob.len, fp, sizeof(fp));
    printf("%s\n", fp);
    return 0;
}
