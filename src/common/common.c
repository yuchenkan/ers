#include <lib/syscall.h>
#include <lib/malloc.h>
#include <common/common.h>

void
eri_build_path (const char *path, const char *name, uint64_t id, char *buf)
{
  eri_strcpy (buf, path);
  buf += eri_strlen (path);
  *buf++ = '/';
  eri_strcpy (buf, name);
  buf += eri_strlen (name);
  char a[eri_itoa_size (id)];
  eri_assert_itoa (id, a, 16);
  uint8_t l = eri_strlen (a);
  uint8_t i;
  for (i = 0; i < (l + 3) / 4 * 4 - l; ++i)
    *buf++ = '0';
  eri_strcpy (buf, a);
}

eri_file_t
eri_open_path (const char *path, const char *name, uint64_t id,
	       void *buf, uint64_t buf_size)
{
  char full_name[eri_build_path_len (path, name, id)];
  eri_build_path (path, name, id, full_name);
  return eri_assert_fopen (full_name, 0, buf, buf_size);
}

void
eri_malloc_open_path (struct eri_mtpool *pool,
	struct eri_buf_file *file, const char *path, const char *name,
	uint64_t id, uint64_t buf_size)
{
  file->buf = buf_size ? eri_assert_mtmalloc (pool, buf_size) : 0;
  file->file = eri_open_path (path, name, id, file->buf, buf_size);
}

void
eri_free_close (struct eri_mtpool *pool, struct eri_buf_file *file)
{
  eri_assert_fclose (file->file);
  if (file->buf) eri_assert_mtfree (pool, file->buf);
}

void
eri_mkdir (const char *path)
{
  eri_assert (path[0]);
  char b[eri_strlen (path) + 1];
  eri_strcpy (b, path);
  uint8_t l = b[0] == '/';
  char *p;
  for (p = b + 1; *p; ++p)
    if (*p == '/' && ! l)
      {
	*p = '\0';
	eri_assert_sys_mkdir (b, 0755);
	*p = '/';
	l = 1;
      }
    else if (*p != '/') l = 0;
  eri_assert_sys_mkdir (b, 0755);
}
