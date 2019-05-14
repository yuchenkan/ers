/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#include <lib/printf-common.h>

int32_t m4_ns(fopen) (const char *path, uint8_t r, eri_file_t *file,
		      void *buf, uint64_t buf_size);
int32_t m4_ns(fclose) (eri_file_t file);

#define m4_ns(assert_fopen)(path, r, buf, buf_size) \
  ({ eri_file_t _file;							\
     eri_assert (m4_ns(fopen) (path, r, &_file, buf, buf_size) == 0);	\
     _file; })
#define m4_ns(assert_fclose)(file) \
  eri_assert (m4_ns(fclose) (file) == 0)

#if 0
int32_t m4_ns(frelease) (eri_file_t file, int32_t *fd);
#define m4_ns(assert_frelease)(file) \
  ({ int32_t __fd; eri_assert (m4_ns(frelease) (file, &__fd) == 0); __fd; })
#endif

int32_t m4_ns(fseek) (eri_file_t file, int64_t offset, uint8_t rel,
		      uint64_t *res_offset);

#define m4_ns(assert_fseek)(f, o, r) \
  ({ uint64_t _res; eri_assert (m4_ns(fseek) (f, o, r, &_res) == 0); _res; })

int32_t m4_ns(fwrite) (eri_file_t file,
		       const void *buf, uint64_t size, uint64_t *len);
int32_t m4_ns(fread) (eri_file_t file,
		      void *buf, uint64_t size, uint64_t *len);

#define m4_ns(assert_fwrite)(f, buf, sz, len) \
  eri_assert (m4_ns(fwrite) (f, buf, sz, len) == 0)
#define m4_ns(assert_fread)(f, buf, sz, len) \
  eri_assert (m4_ns(fread) (f, buf, sz, len) == 0)

/* Support %u %lu %x %lx %s only.  */
int32_t m4_ns(vfprintf) (eri_file_t file, const char *fmt, va_list arg);
int32_t m4_ns(fprintf) (eri_file_t file, const char *fmd, ...);

int32_t m4_ns(vprintf) (const char *fmt, va_list arg);
int32_t m4_ns(printf) (const char *fmt, ...);

#define m4_ns(assert_vfprintf)(f, fmt, arg) \
  eri_assert (m4_ns(vfprintf) (f, fmt, arg) == 0)
#define m4_ns(assert_fprintf)(f, fmt, ...) \
  eri_assert (m4_ns(fprintf) (f, fmt, ##__VA_ARGS__) == 0)
#define m4_ns(assert_vprintf)(fmt, arg) \
  eri_assert (m4_ns(vprintf) (fmt, arg) == 0)
#define m4_ns(assert_printf)(fmt, ...) \
  eri_assert (m4_ns(printf) (fmt, ##__VA_ARGS__) == 0)

int32_t m4_ns(lvfprintf) (struct eri_lock *lock, eri_file_t file,
		       const char *fmt, va_list arg);
int32_t m4_ns(lfprintf) (struct eri_lock *lock, eri_file_t file,
		      const char *fmt, ...);

int32_t m4_ns(lvprintf) (struct eri_lock *lock,
			 const char *fmt, va_list arg);
int32_t m4_ns(lprintf) (struct eri_lock *lock, const char *fmt, ...);

#define m4_ns(assert_lvfprintf)(l, f, fmt, arg) \
  eri_assert (m4_ns(lvfprintf) (l, f, fmt, arg) == 0)
#define m4_ns(assert_lfprintf)(l, f, fmt, ...) \
  eri_assert (m4_ns(lfprintf) (l, f, fmt, ##__VA_ARGS__) == 0)
#define m4_ns(assert_lvprintf)(l, fmt, arg) \
  eri_assert (m4_ns(lvprintf) (l, fmt, arg) == 0)
#define m4_ns(assert_lprintf)(l, fmt, ...) \
  eri_assert (m4_ns(lprintf) (l, fmt, ##__VA_ARGS__) == 0)

int32_t m4_ns(file_foreach_line) (const char *path, struct eri_buf *buf,
		void (*proc) (const char *, uint64_t, void *), void *data);

#define m4_ns(assert_file_foreach_line)(path, buf, proc, data) \
  eri_assert (m4_ns(file_foreach_line) (path, buf, proc, data) == 0)
