#include <stdint.h>

#include "lib/tst/tst-util.h"

#include "lib/util.h"
#include "lib/malloc.h"
#include "lib/syscall.h"

static uint8_t buf2[64 * 1024 * 1024];

int32_t
main (void)
{
  uint8_t buf[1024];
  struct eri_pool pool;
  eri_assert_init_pool (&pool, buf, sizeof buf);
  void *p[4];
  p[0] = eri_assert_malloc (&pool, 1);
  p[1] = eri_assert_malloc (&pool, 2);
  p[2] = eri_assert_malloc (&pool, 3);
  p[3] = eri_assert_malloc (&pool, 4);
  eri_assert_free (&pool, p[0]);
  eri_assert_free (&pool, p[1]);
  eri_assert_free (&pool, p[2]);
  eri_assert_free (&pool, p[3]);
  eri_assert (pool.used == 0);
  eri_assert_fini_pool (&pool);

  struct tst_rand rand;
  tst_rand_seed (&rand, ERI_ASSERT_SYSCALL_RES (gettid));

  eri_assert_init_pool (&pool, buf2, sizeof buf2);
#define MALLOC(p, s) \
  void *p = eri_assert_malloc (&pool, s);				\
  tst_rand_fill (&rand, p, s)

  MALLOC (i, 10344);
  MALLOC (a, 16777216);
  MALLOC (d, 32);
  MALLOC (ds, 262144);
  MALLOC (l, 72);
  MALLOC (mt, 4208);
  MALLOC (me, 448);
  MALLOC (ms, 1048576);
  MALLOC (mfb, 32768);
  MALLOC (tt, 4208);
  MALLOC (te, 448);
  MALLOC (ts, 1048576);
#define FREE(p) \
  eri_assert_free (&pool, p)
  FREE (mfb);
  MALLOC (mlt, 32);
  FREE (mlt);
  FREE (ms);
  FREE (me);
  FREE (mt);
  MALLOC (tfb, 32768);
  FREE (tfb);
  MALLOC (tlt, 32);
  FREE (tlt);
  FREE (l);
  FREE (ds);
  FREE (d);
  FREE (ts);
  FREE (te);
  FREE (tt);
  FREE (a);
  FREE (i);

  eri_assert (pool.used == 0);
  eri_assert_fini_pool (&pool);

  return 0;
}
