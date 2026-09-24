#include <string.h>
#include "../core/x11.h"
#include "../core/wire.h"
#include "test.h"

/* Builds one X11 ConnectionSetup request prefix: byte-order 'l' (little-endian, matches this host
 * and virtually every real client), protocol version 11.0, "MIT-MAGIC-COOKIE-1", then `cookie`
 * (must be 16 bytes -- MIT-MAGIC-COOKIE-1's own fixed length, so its own pad is always 0), then
 * optionally `trailing` bytes appended right after (simulating a pipelined first X11 request
 * arriving in the same read). Returns the total length written. */
static size_t build_setup(u8 *out, const u8 cookie[16], const u8 *trailing, size_t trailing_len)
{
    static const char proto[] = "MIT-MAGIC-COOKIE-1";
    size_t plen = strlen(proto), ppad = (4 - (plen % 4)) % 4, o = 0;

    out[o++] = 0x6c; out[o++] = 0;                      /* byte-order 'l', pad */
    out[o++] = 11; out[o++] = 0;                        /* protocol-major-version = 11 (LE) */
    out[o++] = 0;  out[o++] = 0;                        /* protocol-minor-version = 0 */
    out[o++] = (u8)plen; out[o++] = 0;                  /* auth-name length = 19 (LE) */
    out[o++] = 16; out[o++] = 0;                        /* auth-data length = 16 (LE) */
    out[o++] = 0;  out[o++] = 0;                        /* pad */
    memcpy(out + o, proto, plen); o += plen;
    memset(out + o, 0, ppad); o += ppad;
    memcpy(out + o, cookie, 16); o += 16;
    if (trailing && trailing_len) { memcpy(out + o, trailing, trailing_len); o += trailing_len; }
    return o;
}

static void fill(u8 *p, int base) { int i; for (i = 0; i < 16; i++) p[i] = (u8)(base + i); }

static void test_all_at_once(void)
{
    u8 fake[16], real[16], buf[128];
    size_t total, consumed = 0;
    sbuf out;

    fill(fake, 0x10); fill(real, 0xa0);
    total = build_setup(buf, fake, NULL, 0);

    CHECK(x11_rewrite_setup(buf, total, fake, real, 16, &out, &consumed) == X11_OK);
    CHECK(consumed == total);
    CHECK(out.len == total);                             /* 16-byte cookie replaced by another 16 */
    CHECK(memcmp(out.p, buf, 12 + 19 + 1) == 0);          /* header + name + name's own pad, unchanged */
    CHECK(memcmp(out.p + 12 + 19 + 1, real, 16) == 0);    /* data replaced with the real cookie */
    sb_free(&out);
}

/* The one behavior a single-shot test can't exercise: every prefix length short of the whole
 * thing must report X11_NEED_MORE with no side effects, and only the full prefix succeeds. */
static void test_byte_at_a_time(void)
{
    u8 fake[16], real[16], buf[128];
    size_t total, i, consumed = 0;
    sbuf out;

    fill(fake, 0x20); fill(real, 0xb0);
    total = build_setup(buf, fake, NULL, 0);

    for (i = 1; i < total; i++) CHECK(x11_rewrite_setup(buf, i, fake, real, 16, &out, &consumed) == X11_NEED_MORE);
    CHECK(x11_rewrite_setup(buf, total, fake, real, 16, &out, &consumed) == X11_OK);
    CHECK(consumed == total);
    CHECK(memcmp(out.p + 12 + 19 + 1, real, 16) == 0);
    sb_free(&out);
}

static void test_trailing_bytes(void)
{
    static const u8 extra[] = "hello, x11 traffic";
    u8 fake[16], real[16], buf[160];
    size_t total, consumed = 0;
    sbuf out;

    fill(fake, 0x30); fill(real, 0xc0);
    total = build_setup(buf, fake, extra, sizeof(extra) - 1);

    CHECK(x11_rewrite_setup(buf, total, fake, real, 16, &out, &consumed) == X11_OK);
    CHECK(consumed == total - (sizeof(extra) - 1));       /* the prefix alone, not the trailing data */
    CHECK(memcmp(buf + consumed, extra, sizeof(extra) - 1) == 0);   /* left untouched in the input */
    sb_free(&out);
}

static void test_no_real_cookie(void)
{
    u8 fake[16], buf[128];
    size_t total, consumed = 0;
    sbuf out;

    fill(fake, 0x40);
    total = build_setup(buf, fake, NULL, 0);

    CHECK(x11_rewrite_setup(buf, total, fake, NULL, 0, &out, &consumed) == X11_OK);
    CHECK(consumed == total);
    CHECK(out.len == 12);                                 /* header only, both lengths zeroed */
    CHECK(out.p[6] == 0 && out.p[7] == 0);                 /* auth-name-length := 0 */
    CHECK(out.p[8] == 0 && out.p[9] == 0);                 /* auth-data-length := 0 */
    CHECK(memcmp(out.p, buf, 6) == 0);                     /* byte-order/pad/versions unchanged */
    CHECK(memcmp(out.p + 10, buf + 10, 2) == 0);           /* header's own trailing pad unchanged */
    sb_free(&out);
}

static void test_cookie_mismatch(void)
{
    u8 fake[16], wrong[16], real[16], buf[128];
    size_t total, consumed = 0;
    sbuf out;

    fill(fake, 0x50); fill(wrong, 0x99); fill(real, 0xd0);
    total = build_setup(buf, wrong, NULL, 0);              /* client presents a DIFFERENT cookie */

    CHECK(x11_rewrite_setup(buf, total, fake, real, 16, &out, &consumed) == X11_BAD);
}

static void test_protocol_name_mismatch(void)
{
    u8 fake[16], real[16], buf[128];
    size_t o = 0, total, consumed = 0;
    static const char other[] = "XDM-AUTHORIZATION-1";      /* 19 bytes -- same length as
                                                                MIT-MAGIC-COOKIE-1, a real X11
                                                                auth scheme, so this exercises the
                                                                content check, not just a length
                                                                mismatch that would trivially fail */
    sbuf out;

    fill(fake, 0x60); fill(real, 0xe0);
    buf[o++] = 0x6c; buf[o++] = 0;
    buf[o++] = 11; buf[o++] = 0;
    buf[o++] = 0;  buf[o++] = 0;
    buf[o++] = (u8)strlen(other); buf[o++] = 0;
    buf[o++] = 16; buf[o++] = 0;
    buf[o++] = 0;  buf[o++] = 0;
    memcpy(buf + o, other, strlen(other)); o += strlen(other);
    buf[o++] = 0;                                            /* name's own pad: 19 % 4 == 3, so 1 byte */
    memcpy(buf + o, fake, 16); o += 16;
    total = o;

    CHECK(x11_rewrite_setup(buf, total, fake, real, 16, &out, &consumed) == X11_BAD);
}

static void test_bad_byte_order(void)
{
    u8 fake[16], real[16], buf[128];
    size_t total, consumed = 0;
    sbuf out;

    fill(fake, 0x70); fill(real, 0xf0);
    total = build_setup(buf, fake, NULL, 0);
    buf[0] = 0x00;                                          /* neither 'B' nor 'l' */

    CHECK(x11_rewrite_setup(buf, total, fake, real, 16, &out, &consumed) == X11_BAD);
}

/* A claimed field length far past what any real request needs must be rejected outright, not
 * treated as "need more data" (which would make a hostile peer's absurd claim buffer forever). */
static void test_field_length_bound(void)
{
    u8 fake[16], real[16], buf[64];
    size_t consumed = 0;
    sbuf out;

    fill(fake, 0x80); fill(real, 0x01);
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x6c;
    buf[6] = 0xff; buf[7] = 0x0f;                           /* auth-name length = 4095, way over the bound */

    CHECK(x11_rewrite_setup(buf, sizeof(buf), fake, real, 16, &out, &consumed) == X11_BAD);
}

static void test_short_input_needs_more(void)
{
    u8 fake[16], real[16], buf[8];
    size_t consumed = 0;
    sbuf out;

    fill(fake, 0x90); fill(real, 0x02);
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x6c;

    CHECK(x11_rewrite_setup(buf, sizeof(buf), fake, real, 16, &out, &consumed) == X11_NEED_MORE);
}

int main(void)
{
    test_all_at_once();
    test_byte_at_a_time();
    test_trailing_bytes();
    test_no_real_cookie();
    test_cookie_mismatch();
    test_protocol_name_mismatch();
    test_bad_byte_order();
    test_field_length_bound();
    test_short_input_needs_more();
    TEST_DONE("x11");
}
