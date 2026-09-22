#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "knownhosts.h"
#include "sha1.h"
#include "wire.h"
#include "ssh_key.h"
#include "oscompat.h"

static int lower(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

/* Case-insensitive glob with * and ? */
static int glob_match(const char *pat, size_t pn, const char *s, size_t sn)
{
    while (pn) {
        if (*pat == '*') {
            size_t i;
            pat++; pn--;
            if (!pn) return 1;
            for (i = 0; i <= sn; i++) if (glob_match(pat, pn, s + i, sn - i)) return 1;
            return 0;
        }
        if (!sn) return 0;
        if (*pat != '?' && lower(*pat) != lower(*s)) return 0;
        pat++; pn--; s++; sn--;
    }
    return sn == 0;
}

static int hashed_match(const char *tok, size_t n, const char *name)
{
    /* |1|base64(salt)|base64(hmac-sha1(salt, name)) */
    const char *p, *q;
    u8 salt[64], want[32], got[20];
    int sl, hl;
    if (n < 5 || memcmp(tok, "|1|", 3) != 0) return 0;
    p = tok + 3;
    q = memchr(p, '|', n - 3);
    if (!q) return 0;
    sl = b64_decode(p, (size_t)(q - p), salt, sizeof(salt));
    hl = b64_decode(q + 1, n - (size_t)(q + 1 - tok), want, sizeof(want));
    if (sl <= 0 || hl != 20) return 0;
    hmac_sha1(salt, (size_t)sl, name, strlen(name), got);
    return memcmp(got, want, 20) == 0;
}

static int hosts_match(const char *list, size_t n, const char *name)
{
    size_t i = 0, start;
    int matched = 0;
    while (i <= n) {
        int neg = 0;
        const char *tok;
        size_t tn;
        start = i;
        while (i < n && list[i] != ',') i++;
        tok = list + start; tn = i - start;
        i++;
        if (tn && tok[0] == '!') { neg = 1; tok++; tn--; }
        if (!tn) continue;
        if (hashed_match(tok, tn, name) || glob_match(tok, tn, name, strlen(name))) {
            if (neg) return 0;
            matched = 1;
        }
    }
    return matched;
}

static void make_name(char *out, size_t sz, const char *host, int port)
{
    size_t hl = strlen(host);
    if (port == 22 || port <= 0) {
        if (hl >= sz) hl = sz - 1;
        memcpy(out, host, hl); out[hl] = '\0';
    } else {
        char num[12];
        int n = 0, v = port, k;
        while (v > 0) { num[n++] = (char)('0' + v % 10); v /= 10; }
        if (hl + n + 4 > sz) hl = sz > (size_t)n + 4 ? sz - (size_t)n - 4 : 0;
        out[0] = '[';
        memcpy(out + 1, host, hl);
        out[1 + hl] = ']'; out[2 + hl] = ':';
        for (k = 0; k < n; k++) out[3 + hl + (size_t)k] = num[n - 1 - k];
        out[3 + hl + (size_t)n] = '\0';
    }
}

int kh_check(const char *path, const char *host, int port, const u8 *blob, size_t blen)
{
    FILE *f = fopen(path, "r");
    char line[8192], name[300];
    int result = KH_UNKNOWN;
    char TYPE[40];

    if (!f) return KH_UNKNOWN;
    if (ssh_blob_type(blob, blen, TYPE, sizeof(TYPE)) != 0) { fclose(f); return KH_UNKNOWN; }
    make_name(name, sizeof(name), host, port);
    while (fgets(line, sizeof(line), f)) {
        char *p = line, *hosts, *type, *key;
        size_t hn;
        u8 dec[1024];
        int dl;

        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0' || *p == '@') continue;
        hosts = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) continue;
        hn = (size_t)(p - hosts);
        while (*p == ' ' || *p == '\t') p++;
        type = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (!*p) continue;
        *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;
        key = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
        *p = '\0';

        if (!hosts_match(hosts, hn, name)) continue;
        if (strcmp(type, TYPE) != 0) continue;                 /* other key types: not comparable */
        dl = b64_decode(key, strlen(key), dec, sizeof(dec));
        if (dl < 0) continue;
        if ((size_t)dl == blen && memcmp(dec, blob, blen) == 0) { result = KH_MATCH; break; }
        result = KH_CHANGED;
    }
    fclose(f);
    return result;
}

int kh_add(const char *path, const char *host, int port, const u8 *blob, size_t blen)
{
    FILE *f;
    char name[300], *b64;
    size_t cap = (blen + 2) / 3 * 4 + 4;
    int n;
    char type[40];

    if (ssh_blob_type(blob, blen, type, sizeof(type)) != 0) return -1;
    b64 = (char *)malloc(cap);
    if (!b64) return -1;
    n = b64_encode(blob, blen, b64, cap, 1);
    if (n < 0) { free(b64); return -1; }
    make_name(name, sizeof(name), host, port);
    f = fopen(path, "a");
    if (!f) { free(b64); return -1; }
    chmod(path, 0600);
    fprintf(f, "%s %s %s\n", name, type, b64);
    fclose(f);
    free(b64);
    return 0;
}
