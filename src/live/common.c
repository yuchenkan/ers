#include <lib/util.h>
#include <lib/buf.h>

#include <common/debug.h>
#include <common/common.h>

#include <live/common.h>

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
