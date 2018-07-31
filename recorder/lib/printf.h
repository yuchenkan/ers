#ifndef ERI_PRINTF_H
#define ERI_PRINTF_H

#include <stdarg.h>

int eri_fopen (const char *path, char ro, int *fd);
int eri_fclose (int fd);

int eri_fwrite (int fd, const char *buf, int size);
int eri_fread (int fd, char *buf, int size, int *len);

/* Support %u %lu %x %lx %s only */
int eri_vfprintf (int fd, const char *fmt, va_list arg);
int eri_fprintf (int fd, const char *fmd, ...);

int eri_vprintf (const char *fmt, va_list arg);
int eri_printf (const char *fmt, ...);

#endif
