/*
 * oscompat.h -- prototypes that OPENSTEP 4.2's system headers leave out.
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
 */
#ifndef SSH_OSCOMPAT_H
#define SSH_OSCOMPAT_H

#ifdef OPENSTEP
extern int close(int fd);
extern int getpid(void);
extern int chmod(const char *path, int mode);
extern int mkdir(const char *path, int mode);
#endif

#endif
