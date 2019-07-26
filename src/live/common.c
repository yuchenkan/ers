#include <lib/util.h>
#include <lib/buf.h>
#include <lib/syscall.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/serial.h>
#include <common/entry.h>

#include <live/common.h>

char *
eri_live_alloc_abs_path (struct eri_mtpool *pool, const char *path)
{
  if (! path) return 0;

  if (path[0] == '/')
    {
      char *abs = eri_assert_mtmalloc (pool, eri_strlen (path) + 1);
      eri_strcpy (abs, path);
      return abs;
    }

  char *buf;
  uint64_t size = ERI_PATH_MAX, res;
  while (1)
    {
      buf = eri_assert_mtmalloc (pool, size);
      res = eri_syscall (getcwd, buf, size);
      if (eri_syscall_is_ok (res)) break;
      eri_assert (res == ERI_ERANGE);
      eri_assert_mtfree (pool, buf);
      size *= 2;
    }

  eri_assert (res >= 2);
  uint8_t slash = buf[res - 2] == '/';
  char *abs = eri_assert_mtmalloc (pool, res + ! slash + eri_strlen (path));
  eri_strcpy (abs, buf);
  if (! slash)
    {
      abs[res - 1] = '/';
      eri_strcpy (abs + res, path);
    }
  else eri_strcpy (abs + res - 1, path);
  // eri_info ("%s\n", abs);
  eri_assert_mtfree (pool, buf);
  return abs;
}

struct init_get_map_args
{
  struct eri_mtpool *pool;
  struct eri_buf *buf;
};

static void
init_get_map (const struct eri_smaps_map *map, void *args)
{
  struct init_get_map_args *a = args;
  struct eri_smaps_map m = *map;
  if (map->path)
    {
      m.path = eri_assert_mtmalloc (a->pool, eri_strlen (map->path) + 1);
      eri_strcpy ((void *) m.path, map->path);
    }
  eri_assert_buf_append (a->buf, &m, 1);
}

void
eri_live_init_get_maps (struct eri_mtpool *pool,
			const struct eri_range *map, struct eri_buf *buf)
{
  eri_assert_buf_mtpool_init (buf, pool, 8, struct eri_smaps_map);
  struct init_get_map_args args = { pool, buf };
  eri_init_foreach_map (pool, map, init_get_map, &args);
}

void
eri_live_init_free_maps (struct eri_mtpool *pool, struct eri_buf *buf)
{
  struct eri_smaps_map *maps = buf->buf;
  uint64_t i;
  for (i = 0; i < buf->o; ++i)
    if (maps[i].path) eri_assert_mtfree (pool, (void *) maps[i].path);
  eri_assert_buf_fini (buf);
}

struct eri_live_atomic
{
  struct eri_mtpool *pool;
  uint64_t *table;
  uint64_t table_size;
};

struct eri_live_atomic *
eri_live_create_atomic (struct eri_mtpool *pool, uint64_t table_size)
{
  struct eri_live_atomic *atomic = eri_assert_mtmalloc_struct (
	pool, typeof (*atomic), (table, table_size * sizeof *atomic->table));
  atomic->pool = pool;
  eri_memset (atomic->table, 0, table_size * sizeof *atomic->table);
  atomic->table_size = table_size;
  return atomic;
}

void
eri_live_destroy_atomic (struct eri_live_atomic *atomic)
{
  eri_assert_mtfree (atomic->pool, atomic);
}

static uint64_t
atomic_lock (struct eri_live_atomic *atomic, uint64_t aligned)
{
  uint64_t idx = eri_atomic_hash (aligned, atomic->table_size);

  uint32_t i = 0;
  while (eri_atomic_bit_test_set (atomic->table + idx, 0, 1))
    if (++i % 16 == 0) eri_assert_syscall (sched_yield);
  return idx;
}

uint64_t
eri_live_atomic_get_table_size (struct eri_live_atomic *atomic)
{
  return atomic->table_size;
}

struct eri_pair
eri_live_atomic_lock (struct eri_live_atomic *atomic,
		      uint64_t mem, uint8_t size)
{
  struct eri_pair idx = { atomic_lock (atomic, eri_atomic_aligned (mem)) };
  idx.second = eri_atomic_cross_aligned (mem, size)
	? atomic_lock (atomic, eri_atomic_aligned2 (mem, size)) : idx.first;
  return idx;
}

static void
atomic_unlock (struct eri_live_atomic *atomic, uint64_t idx)
{
  eri_atomic_and (atomic->table + idx, -2, 1);
}

struct eri_pair
eri_live_atomic_unlock (struct eri_live_atomic *atomic,
			struct eri_pair *idx, uint8_t ok)
{
  uint8_t cross = idx->first != idx->second;
  struct eri_pair ver = {
    atomic->table[idx->first] >> 1,
    atomic->table[idx->second] >> 1
  };

  if (ok)
    {
      atomic->table[idx->first] += 2;
      if (cross) atomic->table[idx->second] += 2;
    }

  atomic_unlock (atomic, idx->first);
  if (cross) atomic_unlock (atomic, idx->second);
  return ver;
}

void
eri_live_atomic (struct eri_live_atomic *atomic,
		 struct eri_live_atomic_args *args)
{
  uint64_t mem = (uint64_t) args->mem;
  uint8_t size = args->size;
  struct eri_pair idx = eri_live_atomic_lock (atomic, mem, size);

  struct eri_atomic_record *rec = args->rec;
  if (! eri_entry__test_access (args->entry, args->mem, 0))
    {
      eri_live_atomic_unlock (atomic, &idx, 0);
      rec->ok = 0;
      return;
    }

  /* XXX: invalid argument from user */
  eri_lassert (args->log, eri_atomic (args->code, args->mem, size,
				      args->val, args->old, args->rflags));

  eri_entry__reset_test_access (args->entry);

  rec->ok = 1;
  rec->ver = eri_live_atomic_unlock (atomic, &idx, 1);
}
