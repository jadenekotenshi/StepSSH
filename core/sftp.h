/*
 * sftp.h -- SFTP protocol version 3 client (draft-ietf-secsh-filexfer-02, as spoken by
 * OpenSSH's sftp-server), sans-I/O like the SSH engine.
 *
 * Bytes received on the "sftp" subsystem channel go to sftp_input(); whatever
 * sftp_output() exposes goes back out on the channel.  Every request takes a callback
 * that runs (from inside sftp_input) when its response arrives.  Callbacks may issue
 * further requests.  Pointers in an sftp_response are valid only during the callback.
 */
#ifndef SSH_SFTP_H
#define SSH_SFTP_H

#include <stdio.h>
#include "ssh_types.h"

typedef struct sftp sftp;

/* attribute presence flags */
#define SFTP_ATTR_SIZE        0x00000001UL
#define SFTP_ATTR_UIDGID      0x00000002UL
#define SFTP_ATTR_PERMISSIONS 0x00000004UL
#define SFTP_ATTR_ACMODTIME   0x00000008UL

typedef struct {
    u32 flags;
    u64 size;
    u32 uid, gid, perms, atime, mtime;
} sftp_attrs;

/* st_mode helpers on attrs.perms */
#define SFTP_S_ISDIR(p) (((p) & 0170000UL) == 0040000UL)
#define SFTP_S_ISLNK(p) (((p) & 0170000UL) == 0120000UL)
#define SFTP_S_ISREG(p) (((p) & 0170000UL) == 0100000UL)

/* open flags */
#define SFTP_OPEN_READ   0x01UL
#define SFTP_OPEN_WRITE  0x02UL
#define SFTP_OPEN_APPEND 0x04UL
#define SFTP_OPEN_CREAT  0x08UL
#define SFTP_OPEN_TRUNC  0x10UL
#define SFTP_OPEN_EXCL   0x20UL

/* response types */
enum { SFTP_R_STATUS = 101, SFTP_R_HANDLE = 102, SFTP_R_DATA = 103, SFTP_R_NAME = 104, SFTP_R_ATTRS = 105 };
/* status codes */
enum { SFTP_OK = 0, SFTP_EOF = 1, SFTP_NO_SUCH_FILE = 2, SFTP_PERMISSION_DENIED = 3, SFTP_FAILURE = 4,
       SFTP_BAD_MESSAGE = 5, SFTP_NO_CONNECTION = 6, SFTP_CONNECTION_LOST = 7, SFTP_OP_UNSUPPORTED = 8 };

typedef struct {
    char       *name;                     /* NUL-terminated copies */
    char       *longname;
    sftp_attrs  attrs;
} sftp_name;

typedef struct {
    u32         id;
    int         type;                     /* SFTP_R_* */
    u32         status;                   /* STATUS: SFTP_OK, SFTP_EOF, ... */
    const char *message;                  /* STATUS: server's text, or a local description */
    const u8   *handle;  size_t handle_len;   /* HANDLE */
    const u8   *data;    size_t data_len;     /* DATA */
    int         nnames;  const sftp_name *names;   /* NAME */
    sftp_attrs  attrs;                    /* ATTRS */
} sftp_response;

typedef void (*sftp_cb)(sftp *s, const sftp_response *r, void *ctx);

sftp *sftp_new(void);
void  sftp_free(sftp *s);
/* Queue the INIT packet.  `ready` (may be NULL) runs when the server's VERSION arrives. */
int   sftp_start(sftp *s, void (*ready)(sftp *s, void *ctx), void *ctx);
/* Feed bytes from the channel.  Returns 0, or -1 after a protocol error (sftp_error() says why). */
int   sftp_input(sftp *s, const u8 *data, size_t len);
const u8 *sftp_output(sftp *s, size_t *len);
void  sftp_output_done(sftp *s, size_t n);
int   sftp_is_ready(const sftp *s);
const char *sftp_error(const sftp *s);          /* NULL while healthy */
size_t sftp_pending(const sftp *s);             /* requests still awaiting a response */
/* The channel died: every pending request completes with SFTP_CONNECTION_LOST. */
void  sftp_abort(sftp *s, const char *why);

/* ---- requests: each returns the request id, or 0 if it could not be queued ---- */
u32 sftp_opendir(sftp *s, const char *path, sftp_cb cb, void *ctx);
u32 sftp_readdir(sftp *s, const u8 *h, size_t hl, sftp_cb cb, void *ctx);
u32 sftp_close(sftp *s, const u8 *h, size_t hl, sftp_cb cb, void *ctx);
u32 sftp_open(sftp *s, const char *path, u32 pflags, u32 mode, sftp_cb cb, void *ctx);   /* mode 0 = server default */
u32 sftp_read(sftp *s, const u8 *h, size_t hl, u64 offset, u32 len, sftp_cb cb, void *ctx);
u32 sftp_write(sftp *s, const u8 *h, size_t hl, u64 offset, const u8 *data, u32 len, sftp_cb cb, void *ctx);
u32 sftp_stat(sftp *s, const char *path, sftp_cb cb, void *ctx);
u32 sftp_lstat(sftp *s, const char *path, sftp_cb cb, void *ctx);
u32 sftp_setmode(sftp *s, const char *path, u32 mode, sftp_cb cb, void *ctx);
u32 sftp_mkdir(sftp *s, const char *path, u32 mode, sftp_cb cb, void *ctx);
u32 sftp_rmdir(sftp *s, const char *path, sftp_cb cb, void *ctx);
u32 sftp_remove(sftp *s, const char *path, sftp_cb cb, void *ctx);
u32 sftp_rename(sftp *s, const char *from, const char *to, sftp_cb cb, void *ctx);
u32 sftp_realpath(sftp *s, const char *path, sftp_cb cb, void *ctx);
u32 sftp_readlink(sftp *s, const char *path, sftp_cb cb, void *ctx);

/* ---- directory listing: OPENDIR + READDIR until EOF + CLOSE, collected in one array ---- */
typedef struct sftp_dirlist sftp_dirlist;
typedef void (*sftp_dirlist_cb)(sftp_dirlist *d, void *ctx);      /* called once, on success or failure */
sftp_dirlist *sftp_list(sftp *s, const char *path, sftp_dirlist_cb cb, void *ctx);
int         sftp_dirlist_ok(const sftp_dirlist *d);
const char *sftp_dirlist_error(const sftp_dirlist *d);
int         sftp_dirlist_count(const sftp_dirlist *d);
const sftp_name *sftp_dirlist_entry(const sftp_dirlist *d, int i);
void        sftp_dirlist_free(sftp_dirlist *d);                   /* only after the callback has run */

/* ---- pipelined file transfers ---- */
typedef struct sftp_xfer sftp_xfer;
typedef void (*sftp_xfer_cb)(sftp_xfer *x, void *ctx);            /* on every progress step and on completion */
enum { SFTP_XFER_RUNNING = 0, SFTP_XFER_DONE, SFTP_XFER_FAILED, SFTP_XFER_CANCELLED };
/* `out`/`in` stay owned by the caller.  size_hint 0 = unknown (an EOF status ends the download). */
sftp_xfer *sftp_download(sftp *s, const char *remote, FILE *out, u64 size_hint, sftp_xfer_cb cb, void *ctx);
sftp_xfer *sftp_upload(sftp *s, const char *remote, FILE *in, u32 mode, u64 size_hint, sftp_xfer_cb cb, void *ctx);
int         sftp_xfer_state(const sftp_xfer *x);
u64         sftp_xfer_bytes(const sftp_xfer *x);
u64         sftp_xfer_total(const sftp_xfer *x);                  /* 0 if unknown */
const char *sftp_xfer_error(const sftp_xfer *x);
void        sftp_xfer_cancel(sftp_xfer *x);                       /* finishes (CANCELLED) once in-flight requests drain */
void        sftp_xfer_free(sftp_xfer *x);                         /* only when state != RUNNING */

#endif
