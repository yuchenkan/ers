#include <lib/buf.h>
#include <lib/syscall.h>
#include <lib/malloc.h>

#include <common/debug.h>
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

static void
proc_smap_map (char *buf,
	void (*proc) (const struct eri_smaps_map *, void *), void *args)
{
  struct eri_smaps_map map = { .path = 0, .grows_down = 0 };

  const char *b = buf;
  const char *d = eri_strtok (b, '-');
  *(char *) d = '\0';
  map.range.start = eri_assert_atoi (b, 16);

  d = eri_strtok (b = d + 1, ' ');
  *(char *) d = '\0';
  map.range.end = eri_assert_atoi (b, 16);

  eri_assert (d[1] && d[2] && d[3] && d[4] && d[5] && d[6]);
  map.prot = (d[1] != '-' ? ERI_PROT_READ : 0)
	      | (d[2] != '-' ? ERI_PROT_WRITE : 0)
	      | (d[3] != '-' ? ERI_PROT_EXEC : 0);
  eri_assert (d[4] == 'p'); /* XXX: handle error */

  eri_assert (d = eri_strtok (d + 6, ' '));
  eri_assert (d = eri_strtok (d + 1, ' '));
  eri_assert (d = eri_strtok (d + 1, ' '));
  while (*d && *d == ' ') ++d;

  eri_assert (*d);
  if (*d != '\n')
    {
      map.path = d;
      d = eri_strtok (d, '\n');
    }
  *(char *) d = '\0';

  d = eri_strstr (d + 1, "VmFlags: ");
  eri_assert (d);
  for (d = d + eri_strlen ("VmFlags: "); *d && *d != '\n'; d += 3)
    {
      eri_assert (d[0] && d[1] && d[2]);
      if (d[0] == 'g' && d[1] == 'd')
	{
	  map.grows_down = 1;
	  break;
	}
    }

  proc (&map, args);
}

struct proc_smaps_line_args
{
  void (*proc) (const struct eri_smaps_map *, void *);
  void *args;

  uint32_t line_count;
  struct eri_buf buf;
};

static void
proc_smaps_line (const char *line, uint64_t len, void *args)
{
  struct proc_smaps_line_args *a = args;
  eri_assert_buf_append (&a->buf, line, len);
  if (++a->line_count % 20)
    {
      char nl = '\n';
      eri_assert_buf_append (&a->buf, &nl, 1);
    }
  else
    {
      char e = '\0';
      eri_assert_buf_append (&a->buf, &e, 1);
      proc_smap_map (eri_buf_release (&a->buf), a->proc, a->args);
    }
}

void
eri_smaps_foreach_map (const char *smaps, struct eri_mtpool *pool,
	void (*proc) (const struct eri_smaps_map *, void *), void *args)
{
  struct eri_buf buf;
  eri_assert_buf_mtpool_init (&buf, pool, 256);

  struct proc_smaps_line_args line_args = { proc, args };
  eri_assert_buf_mtpool_init (&line_args.buf, pool, 1024);

  eri_assert_file_foreach_line (smaps, &buf, proc_smaps_line, &line_args);

  eri_assert_buf_fini (&line_args.buf);
  eri_assert_buf_fini (&buf);
}

struct init_proc_map_args
{
  const struct eri_range *map;

  void (*proc) (const struct eri_smaps_map *, void *);
  void *args;
};

static void
init_proc_map (const struct eri_smaps_map *map, void *args)
{
  struct init_proc_map_args *a = args;

  uint64_t start = map->range.start;
  uint64_t end = map->range.end;
  uint64_t map_start = a->map->start;
  uint64_t map_end = a->map->end;

  if (! (end <= map_start || start >= map_end))
    {
      eri_xassert (start >= map_start && end <= map_end, eri_info);
      return;
    }

  const char *path = map->path;
  if (path && eri_strcmp (path, "[vsyscall]") == 0) return;

  a->proc (map, a->args);
}

void
eri_init_foreach_map (struct eri_mtpool *pool, const struct eri_range *map,
	void (*proc) (const struct eri_smaps_map *, void *), void *args)
{
  struct init_proc_map_args map_args = { map, proc, args };
  eri_smaps_foreach_map ("/proc/self/smaps", pool,
			 init_proc_map, &map_args);
}
