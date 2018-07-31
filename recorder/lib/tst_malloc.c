#include "util.h"
#include "malloc.h"

int main ()
{
  char buf[1024];
  struct ers_pool pool;
  ers_assert (ers_init_pool (&pool, buf, sizeof buf) == 0);
  void *p[4];
  ers_assert (ers_malloc (&pool, 1, &p[0]) == 0);
  ers_assert (ers_malloc (&pool, 2, &p[1]) == 0);
  ers_assert (ers_malloc (&pool, 3, &p[2]) == 0);
  ers_assert (ers_malloc (&pool, 4, &p[3]) == 0);
  ers_assert (ers_free (&pool, p[0]) == 0);
  ers_assert (ers_free (&pool, p[1]) == 0);
  ers_assert (ers_free (&pool, p[2]) == 0);
  ers_assert (ers_free (&pool, p[3]) == 0);
  return 0;
}
