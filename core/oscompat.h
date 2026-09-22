/*
 * oscompat.h -- prototypes (and a couple of missing types) that OPENSTEP 4.2's system headers
 * leave out.
 *
 * Its <unistd.h>, <sys/stat.h> etc. predate ANSI prototypes for several plain
 * POSIX calls, so gcc reports "implicit declaration".  Only functions that were
 * actually reported are listed here: redeclaring one the headers DO declare
 * could cause a "conflicting types" error.
 *
 * Include this AFTER every system header in a file.  It is empty unless the
 * OPENSTEP build (-DOPENSTEP) is in effect, so host builds are unaffected.
 * Argument types are int/pointer everywhere, which matches the i386 calling
 * convention whatever the headers' own typedefs (mode_t, pid_t) are.
 *
 * select()'s declaration below needs fd_set and struct timeval already visible, so a file that
 * uses select() must include <sys/types.h> (fd_set) and <sys/time.h> (struct timeval) itself
 * before this header, same as it would for any other system header's types -- there is no
 * <sys/select.h> on OPENSTEP 4.2 to pull those in together (that split is a POSIX.1-2001
 * convention, a good decade newer).
 */
#ifndef SSH_OSCOMPAT_H
#define SSH_OSCOMPAT_H

#ifdef OPENSTEP
extern int close(int fd);
extern int getpid(void);
extern int chmod(const char *path, int mode);
extern int mkdir(const char *path, int mode);
extern int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                  struct timeval *timeout);
typedef int ssize_t;      /* no ssize_t at all: POSIX.1-1990 has it, but OPENSTEP 4.2 predates
                            * even that catching up in its own headers. int matches read()/write()'s
                            * actual i386 ABI return width here, same reasoning as the note above. */
#endif

#endif
