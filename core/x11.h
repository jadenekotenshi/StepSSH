/*
 * x11.h -- rewrites the X11 ConnectionSetup request's authentication fields as they flow
 * across a forwarded "x11" SSH channel (RFC 4254 s.6.3.1/s.7). Not sans-I/O in the sense of
 * ssh.h/sftp.h (there is no state to carry between calls beyond what the caller already owns) --
 * just one pure, bounds-checked rewrite function, called from core/ssh_chan.c.
 *
 * Why this exists: this client advertises a random "fake" 16-byte cookie to the server via
 * x11-req, purely so a later server-initiated "x11" channel open can be recognized as one we
 * actually asked for. That fake cookie means nothing to the real local X server the forwarded
 * connection is ultimately headed to -- the first data received on each new x11 channel (the X11
 * protocol's own ConnectionSetup request, sent by whatever X11 client the remote side is running)
 * has the fake cookie substituted for a real one before it is ever relayed onward.
 */
#ifndef SSH_X11_H
#define SSH_X11_H

#include "ssh_types.h"
#include "wire.h"

#define X11_AUTH_PROTO  "MIT-MAGIC-COOKIE-1"
#define X11_COOKIE_LEN  16

enum { X11_NEED_MORE = 0, X11_OK = 1, X11_BAD = -1 };

/*
 * `buf`/`len`: bytes accumulated so far from CHANNEL_DATA on a fresh x11 channel (may span
 * several calls, as more arrives). `fake_cookie`: the 16 bytes this session advertised via
 * x11-req. `real_cookie`/`real_cookie_len`: the cookie to substitute in (0 or X11_COOKIE_LEN,
 * enforced by the caller -- 0 means "send no authentication data onward at all").
 *
 * Returns X11_NEED_MORE if `len` bytes aren't yet enough to know the request's full length (the
 * caller should keep accumulating and call again with more data); X11_OK if the request's
 * authentication prefix was found, verified against fake_cookie/X11_AUTH_PROTO, and rewritten --
 * the rewritten bytes are appended to `out` (freshly sb_init'd by the caller) and `*consumed` is
 * how many bytes of `buf` were that prefix (any bytes in `buf` beyond `*consumed` are ordinary
 * X11 traffic, untouched by this call, relayed as-is by the caller); or X11_BAD if the input is
 * malformed, or its protocol name/cookie do not match what was advertised (this channel's
 * connection was never legitimately opened by our own x11-req, or is corrupt) -- the caller
 * should close just this one channel, not the whole session.
 */
int x11_rewrite_setup(const u8 *buf, size_t len,
                       const u8 fake_cookie[X11_COOKIE_LEN],
                       const u8 *real_cookie, size_t real_cookie_len,
                       sbuf *out, size_t *consumed);

#endif
