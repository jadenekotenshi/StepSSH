/*
 * clicommon.h -- pieces shared by StepSSH's command-line tools (stepssh, stepscp): dialing out,
 * OpenSSH-style known_hosts trust-on-first-use, and terminal prompting (password entry with echo
 * off, yes/no confirmation, raw mode for interactive pty forwarding).
 *
 * Plain C89/POSIX, meant to build under both the host Makefile and Makefile.openstep.
 */
#ifndef CLICOMMON_H
#define CLICOMMON_H
#include <stdio.h>
#include "../core/ssh_types.h"

/* Connect a TCP socket to host:service ("service" may be a numeric port as a string).  Returns
 * a connected fd, or -1 (with a message already printed to stderr naming `tool`). */
int cli_dial(const char *tool, const char *host, const char *service);

/* Is `m` present in a comma-separated method list (an SSH_EV_AUTH_NEEDED/FAILED event's text)? */
int cli_has_method(const char *list, const char *m);

/* Prompt on the controlling terminal with echo disabled and read one line (trailing newline
 * stripped) into a static buffer valid until the next call -- ssh_wipe() it when done with it.
 * Fails (returns NULL, "<tool>: ..." message on stderr) if stdin is not a terminal: unlike a
 * passphrase typed once at a shell, a non-interactive stdin is something else's -- treating it as
 * a password source would silently consume input the caller did not mean for this. */
char *cli_read_secret(const char *tool, const char *prompt);

/* Ask a yes/no question on the controlling terminal.  Returns 1/0; if stdin is not a terminal,
 * returns 0 (refuse) without prompting -- the same fail-closed default `ssh` itself uses when it
 * cannot interactively confirm something security-relevant. */
int cli_confirm(const char *prompt);

/* "<HOME>/.ssh/known_hosts", in a static buffer; "./known_hosts" if HOME is unset. */
const char *cli_default_known_hosts(void);

/* One host-key event, OpenSSH's own trust-on-first-use flow: a match is accepted silently; an
 * unknown host is a yes/no prompt (see cli_confirm) that, on yes, is appended to known_hosts; a
 * *changed* key is refused by default with a loud warning (this is the one case cli_confirm's
 * usual meaning is inverted for safety -- accepting it takes a second, explicit yes).  `quiet`
 * suppresses the routine "permanently added" notice but never the changed-key warning.  Returns
 * 1 to accept the key for this connection, 0 to refuse it. */
int cli_check_hostkey(const char *tool, const char *known_hosts_path, const char *host, int port,
                      const u8 *blob, size_t blen, const char *fp, const char *keytype, int quiet);

/* Put fd's terminal into raw mode (no echo, no line buffering, no local signal generation, 8-bit
 * clean) for interactive pty forwarding -- so every keystroke, including control characters,
 * reaches the remote side untouched, exactly as a real terminal-forwarding ssh client requires.
 * No-op if fd is not a terminal.  Returns an opaque token to pass to cli_raw_restore(), or -1 if
 * fd was not a terminal (cli_raw_restore() is then also a no-op). */
int cli_raw_enter(int fd);
void cli_raw_restore(int fd, int token);

/* Split "[user@]host" (a copy of `arg`, never modified) into malloc'd `*user`/`*host`.  With no
 * "user@" part, `*user` becomes a copy of `deflogin` (which must not be NULL). */
void cli_split_userhost(const char *arg, const char *deflogin, char **user, char **host);

/* The current user's login name (getlogin(), then $LOGNAME/$USER, then getpwuid(getuid())), or
 * NULL if none of those work -- a static buffer valid until the next call. */
const char *cli_current_user(void);

/* strdup() by hand: strdup is a BSD/POSIX extension, not ISO C89, so it is not guaranteed to be
 * declared by OPENSTEP 4.2's <string.h>; calling an undeclared function that returns a pointer
 * makes the compiler implicitly assume it returns int instead, which silently truncates the real
 * pointer on any platform where int and a pointer differ in size -- a corrupted-pointer bug with
 * no compiler warning, not a build error. Unlike core/ (a library, which always reports "out of
 * memory" back to its caller rather than aborting), this exits on malloc failure: these are
 * short, single-purpose command-line tools with no meaningful way to run low on memory partway
 * through and no caller to report back to except the shell that ran them. */
char *cli_xstrdup(const char *s);

#endif
