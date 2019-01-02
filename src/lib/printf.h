#ifndef ERI_LIB_PRINTF_H
#define ERI_LIB_PRINTF_H

#include <stdarg.h>
#include <stdint.h>

#include "lib/util.h"
#include "lib/buf.h"

typedef uint64_t eri_file_t;
#define eri_file_buf_t			uint8_t __attribute__ ((aligned (16)))

#define _ERI_FILE_RAW			1

#define _ERI_RAW_FILE_FROM_FD(fd) \
  ((eri_file_t) ((fd) << 4 | _ERI_FILE_RAW))

#define ERI_STDIN			_ERI_RAW_FILE_FROM_FD (0)
#define ERI_STDOUT			_ERI_RAW_FILE_FROM_FD (1)
#define ERI_STDERR			_ERI_RAW_FILE_FROM_FD (2)

int32_t eri_fopen (const char *path, uint8_t r, eri_file_t *file,
		   void *buf, uint64_t buf_size);
int32_t eri_fclose (eri_file_t file);

#define eri_assert_fopen(path, r, file, buf, buf_size) \
  eri_assert (eri_fopen (path, r, file, buf, buf_size) == 0)
#define eri_assert_fclose(file)		 eri_assert (eri_fclose (file) == 0)

#if 0
int32_t eri_frelease (eri_file_t file, int32_t *fd);
#define eri_assert_frelease(file) \
  ({ int32_t __fd; eri_assert (eri_frelease (file, &__fd) == 0); __fd; })
#endif

int32_t eri_fseek (eri_file_t file, int64_t offset, int32_t whence,
		   uint64_t *res_offset);

int32_t eri_fwrite (eri_file_t file,
		    const void *buf, uint64_t size, uint64_t *len);
int32_t eri_fread (eri_file_t file, void *buf, uint64_t size, uint64_t *len);

#define eri_assert_fwrite(f, buf, sz, len) \
  eri_assert (eri_fwrite (f, buf, sz, len) == 0)
#define eri_assert_fread(f, buf, sz, len) \
  eri_assert (eri_fread (f, buf, sz, len) == 0)

/* Support %u %lu %x %lx %s only */
int32_t eri_vfprintf (eri_file_t file, const char *fmt, va_list arg);
int32_t eri_fprintf (eri_file_t file, const char *fmd, ...);

int32_t eri_vprintf (const char *fmt, va_list arg);
int32_t eri_printf (const char *fmt, ...);

#define eri_assert_vfprintf(f, fmt, arg) \
  eri_assert (eri_vfprintf (f, fmt, arg) == 0)
#define eri_assert_fprintf(f, fmt, ...) \
  eri_assert (eri_fprintf (f, fmt, ##__VA_ARGS__) == 0)
#define eri_assert_vprintf(fmt, arg) \
  eri_assert (eri_vprintf (fmt, arg) == 0)
#define eri_assert_printf(fmt, ...) \
  eri_assert (eri_printf (fmt, ##__VA_ARGS__) == 0)

int32_t eri_lvfprintf (int32_t *lock, eri_file_t file,
		       const char *fmt, va_list arg);
int32_t eri_lfprintf (int32_t *lock, eri_file_t file,
		      const char *fmt, ...);

int32_t eri_lvprintf (int32_t *lock, const char *fmt, va_list arg);
int32_t eri_lprintf (int32_t *lock, const char *fmt, ...);

#define eri_assert_lvfprintf(l, f, fmt, arg) \
  eri_assert (eri_lvfprintf (l, f, fmt, arg) == 0)
#define eri_assert_lfprintf(l, f, fmt, ...) \
  eri_assert (eri_lfprintf (l, f, fmt, ##__VA_ARGS__) == 0)
#define eri_assert_lvprintf(l, fmt, arg) \
  eri_assert (eri_lvprintf (l, fmt, arg) == 0)
#define eri_assert_lprintf(l, fmt, ...) \
  eri_assert (eri_lprintf (l, fmt, ##__VA_ARGS__) == 0)

#define eri_assert_clvfprintf(mt, l, f, fmt, arg) \
  eri_assert ((mt) ? eri_lvfprintf (l, f, fmt, arg)			\
		   : eri_vfprintf (f, fmt, arg) == 0)
#define eri_assert_clfprintf(mt, l, f, fmt, ...) \
  eri_assert ((mt) ? eri_lfprintf (l, f, fmt, ##__VA_ARGS__)		\
		   : eri_fprintf (f, fmt, ##__VA_ARGS__) == 0)
#define eri_assert_clvprintf(mt, l, fmt, arg) \
  eri_assert ((mt) ? eri_lvprintf (l, fmt, arg)				\
		   : eri_vprintf (fmt, arg))
#define eri_assert_clprintf(mt, l, fmt, ...) \
  eri_assert ((mt) ? eri_lprintf (l, fmt, ##__VA_ARGS__)		\
		   : eri_printf (fmt, ##__VA_ARGS__))

int32_t eri_file_foreach_line (const char *path, struct eri_buf *buf,
			       void (*proc) (const char *, uint64_t, void *),
			       void *data);

#endif
