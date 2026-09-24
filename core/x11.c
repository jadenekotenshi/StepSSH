/* x11.c -- see x11.h. */
#include <string.h>
#include "x11.h"

/* Generous bound on the auth-protocol-name/auth-protocol-data lengths a ConnectionSetup request
 * claims: real values are tiny (a protocol name, a 16-byte cookie) -- this just keeps a hostile
 * peer from claiming an absurd length and forcing unbounded buffering before we ever decide
 * X11_OK/X11_BAD. */
#define X11_MAX_FIELD 512

static u32 x11_load16(const u8 *p, int little)
{
    return little ? (((u32)p[1] << 8) | p[0]) : (((u32)p[0] << 8) | p[1]);
}

int x11_rewrite_setup(const u8 *buf, size_t len,
                       const u8 fake_cookie[X11_COOKIE_LEN],
                       const u8 *real_cookie, size_t real_cookie_len,
                       sbuf *out, size_t *consumed)
{
    int little;
    u32 name_len, data_len;
    size_t name_pad, data_pad, header_and_name_len, prefix_len;
    const u8 *name, *data;
    static const u8 zero2[2] = { 0, 0 };

    if (len < 12) return X11_NEED_MORE;

    if (buf[0] == 0x6c) little = 1;              /* 'l': little-endian */
    else if (buf[0] == 0x42) little = 0;         /* 'B': big-endian */
    else return X11_BAD;

    name_len = x11_load16(buf + 6, little);
    data_len = x11_load16(buf + 8, little);
    if (name_len > X11_MAX_FIELD || data_len > X11_MAX_FIELD) return X11_BAD;

    name_pad = (4 - (name_len % 4)) % 4;
    data_pad = (4 - (data_len % 4)) % 4;
    header_and_name_len = 12 + (size_t)name_len + name_pad;
    prefix_len = header_and_name_len + (size_t)data_len + data_pad;

    if (len < prefix_len) return X11_NEED_MORE;

    name = buf + 12;
    data = buf + header_and_name_len;

    /* This must be exactly the protocol/cookie we advertised via x11-req -- anything else means
     * this channel's "connection" was never legitimately triggered by our own request. */
    if (name_len != (u32)(sizeof(X11_AUTH_PROTO) - 1) ||
        memcmp(name, X11_AUTH_PROTO, name_len) != 0) return X11_BAD;
    if (data_len != X11_COOKIE_LEN || memcmp(data, fake_cookie, X11_COOKIE_LEN) != 0) return X11_BAD;

    sb_init(out);
    if (real_cookie_len == 0) {
        /* Wire-correct "no authentication": both length fields truncated to zero, name/data
         * omitted entirely. Byte-order/version/the header's own trailing pad are carried over
         * unchanged. */
        sb_put(out, buf, 6);                        /* byte-order, pad, major, minor */
        sb_put(out, zero2, 2);                       /* auth-protocol-name-length := 0 */
        sb_put(out, zero2, 2);                       /* auth-protocol-data-length := 0 */
        sb_put(out, buf + 10, 2);                     /* the header's own trailing pad, as sent */
    } else {
        /* real_cookie_len == X11_COOKIE_LEN (16, same as the fake cookie it replaces, which is
         * always a multiple of 4 -- no padding-length change here), by the caller's own contract.
         * Header + protocol name + the name's own padding carry over unchanged; only the 16-byte
         * data field itself is replaced. */
        sb_put(out, buf, header_and_name_len);
        sb_put(out, real_cookie, X11_COOKIE_LEN);
    }
    if (out->oom) return X11_BAD;                    /* rare; safe to treat like any other bad channel */

    *consumed = prefix_len;
    return X11_OK;
}
