#ifndef ERS_PRINTF_H
#define ERS_PRINTF_H

#include <stdarg.h>

int ers_fopen (const char *path, char ro, int *fd);
int ers_fclose (int fd);

int ers_fwrite (int fd, const char *buf, int size);
int ers_fread (int fd, char *buf, int size, int *len);

/* Support %u %lu %x %lx %s only */
int ers_vfprintf (int fd, const char *fmt, va_list arg);
int ers_fprintf (int fd, const char *fmd, ...);

int ers_vprintf (const char *fmt, va_list arg);
int ers_printf (const char *fmt, ...);

#endif
