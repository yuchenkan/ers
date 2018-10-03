#ifndef ERI_PRINTF_H
#define ERI_PRINTF_H

#include <stdarg.h>
#include <stddef.h>

#include "util.h"
#include "buf.h"

typedef unsigned long eri_file_t;
#define eri_file_buf_t char __attribute__ ((aligned (16)))

#define _ERI_FILE_RAW		1

#define _ERI_RAW_FILE_FROM_FD(fd)	((eri_file_t) ((fd) << 4 | _ERI_FILE_RAW))
#define ERI_STDIN		_ERI_RAW_FILE_FROM_FD (0)
#define ERI_STDOUT		_ERI_RAW_FILE_FROM_FD (1)
#define ERI_STDERR		_ERI_RAW_FILE_FROM_FD (2)

int eri_fopen (const char *path, char r, eri_file_t *file,
	       char *buf, size_t buf_size);
int eri_fclose (eri_file_t file);

int eri_frelease (eri_file_t file, int *fd);
#define eri_assert_frelease(file) \
  ({ int __fd; eri_assert (eri_frelease (file, &__fd) == 0); __fd; })

int eri_fseek (eri_file_t file, long offset, int whence, unsigned long *res_offset);

int eri_fwrite (eri_file_t file, const char *buf, size_t size, size_t *len);
int eri_fread (eri_file_t file, char *buf, size_t size, size_t *len);

/* Support %u %lu %x %lx %s only */
int eri_vfprintf (eri_file_t file, const char *fmt, va_list arg);
int eri_fprintf (eri_file_t file, const char *fmd, ...);

int eri_vprintf (const char *fmt, va_list arg);
int eri_printf (const char *fmt, ...);

int eri_file_foreach_line (const char *path, struct eri_buf *buf,
			   void (*proc) (const void *, size_t, void *), void *data);

#endif
