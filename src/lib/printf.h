#ifndef ERI_LIB_PRINTF_H
#define ERI_LIB_PRINTF_H

#include <stdarg.h>
#include <stdint.h>

#include <lib/util.h>

struct eri_buf;
struct eri_lock;

typedef uint64_t eri_file_t;
#define eri_file_buf_t			uint8_t __attribute__ ((aligned (16)))

#define _ERI_FILE_RAW			1

#define eri_raw_file_from_fd(fd) \
  ((eri_file_t) ((fd) << 4 | _ERI_FILE_RAW))

#define ERI_STDIN			eri_raw_file_from_fd (0)
#define ERI_STDOUT			eri_raw_file_from_fd (1)
#define ERI_STDERR			eri_raw_file_from_fd (2)

int32_t eri_fopen (const char *path, uint8_t r, eri_file_t *file,
		   void *buf, uint64_t buf_size);
int32_t eri_fclose (eri_file_t file);

#define eri_assert_fopen(path, r, buf, buf_size) \
  ({ eri_file_t _file;							\
     eri_assert (eri_fopen (path, r, &_file, buf, buf_size) == 0); _file; })
#define eri_assert_fclose(file)		 eri_assert (eri_fclose (file) == 0)

#if 0
int32_t eri_frelease (eri_file_t file, int32_t *fd);
#define eri_assert_frelease(file) \
  ({ int32_t __fd; eri_assert (eri_frelease (file, &__fd) == 0); __fd; })
#endif

int32_t eri_fseek (eri_file_t file, int64_t offset, uint8_t rel,
		   uint64_t *res_offset);

#define eri_assert_fseek(f, o, r) \
  ({ uint64_t _res; eri_assert (eri_fseek (f, o, r, &_res) == 0); _res; })

int32_t eri_fwrite (eri_file_t file,
		    const void *buf, uint64_t size, uint64_t *len);
int32_t eri_fread (eri_file_t file, void *buf, uint64_t size, uint64_t *len);

#define eri_assert_fwrite(f, buf, sz, len) \
  eri_assert (eri_fwrite (f, buf, sz, len) == 0)
#define eri_assert_fread(f, buf, sz, len) \
  eri_assert (eri_fread (f, buf, sz, len) == 0)

/* Support %u %lu %x %lx %s only.  */
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

int32_t eri_lvfprintf (struct eri_lock *lock, eri_file_t file,
		       const char *fmt, va_list arg);
int32_t eri_lfprintf (struct eri_lock *lock, eri_file_t file,
		      const char *fmt, ...);

int32_t eri_lvprintf (struct eri_lock *lock, const char *fmt, va_list arg);
int32_t eri_lprintf (struct eri_lock *lock, const char *fmt, ...);

#define eri_assert_lvfprintf(l, f, fmt, arg) \
  eri_assert (eri_lvfprintf (l, f, fmt, arg) == 0)
#define eri_assert_lfprintf(l, f, fmt, ...) \
  eri_assert (eri_lfprintf (l, f, fmt, ##__VA_ARGS__) == 0)
#define eri_assert_lvprintf(l, fmt, arg) \
  eri_assert (eri_lvprintf (l, fmt, arg) == 0)
#define eri_assert_lprintf(l, fmt, ...) \
  eri_assert (eri_lprintf (l, fmt, ##__VA_ARGS__) == 0)

int32_t eri_file_foreach_line (const char *path, struct eri_buf *buf,
			       void (*proc) (const char *, uint64_t, void *),
			       void *data);

#define eri_assert_file_foreach_line(path, buf, proc, data) \
  eri_assert (eri_file_foreach_line (path, buf, proc, data) == 0)

#endif
