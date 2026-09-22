#ifndef SSH_KNOWNHOSTS_H
#define SSH_KNOWNHOSTS_H
#include "ssh_types.h"

/* OpenSSH-compatible known_hosts handling (plain, wildcard, negated and
 * hashed "|1|salt|hash" host patterns; [host]:port for non-default ports).
 * @cert-authority / @revoked marker lines are skipped. */
enum { KH_UNKNOWN = 0, KH_MATCH = 1, KH_CHANGED = 2 };

/* Look the host key up.  KH_CHANGED means the host is listed with a
 * *different* key of the same type: treat that as a possible attack. */
int kh_check(const char *path, const char *host, int port, const u8 *blob, size_t blen);
/* Append an entry.  Returns 0 on success.  The file is created with mode 0600. */
int kh_add(const char *path, const char *host, int port, const u8 *blob, size_t blen);

#endif
