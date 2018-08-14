#ifndef ERI_PRINTF_H
#define ERI_PRINTF_H

#include <stdarg.h>
#include <stddef.h>

int eri_fopen (const char *path, char r, int *fd);
int eri_fclose (int fd);

#define ERI_SEEK_SET	0
#define ERI_SEEK_CUR	1
int eri_fseek (int fd, long offset, int whence);

int eri_fwrite (int fd, const char *buf, size_t size);
int eri_fread (int fd, char *buf, size_t size, size_t *len);

/* Support %u %lu %x %lx %s only */
int eri_vfprintf (int fd, const char *fmt, va_list arg);
int eri_fprintf (int fd, const char *fmd, ...);

int eri_vprintf (const char *fmt, va_list arg);
int eri_printf (const char *fmt, ...);

#endif
