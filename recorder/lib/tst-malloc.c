#include "util.h"
#include "malloc.h"

int main ()
{
  char buf[1024];
  struct eri_pool pool;
  eri_assert (eri_init_pool (&pool, buf, sizeof buf) == 0);
  void *p[4];
  eri_assert (eri_malloc (&pool, 1, &p[0]) == 0);
  eri_assert (eri_malloc (&pool, 2, &p[1]) == 0);
  eri_assert (eri_malloc (&pool, 3, &p[2]) == 0);
  eri_assert (eri_malloc (&pool, 4, &p[3]) == 0);
  eri_assert (eri_free (&pool, p[0]) == 0);
  eri_assert (eri_free (&pool, p[1]) == 0);
  eri_assert (eri_free (&pool, p[2]) == 0);
  eri_assert (eri_free (&pool, p[3]) == 0);
  return 0;
}
