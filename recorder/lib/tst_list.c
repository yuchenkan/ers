#include "util.h"
#include "list.h"
#include "printf.h"

struct list
{
  char a;
  ERI_LST_LIST_FIELDS (x);
};

struct node
{
  int a;
  char b;
  ERI_LST_NODE_FIELDS (x);
};

ERI_DECLARE_LIST (static, x, struct list, struct node)
ERI_DEFINE_LIST (static, x, struct list, struct node)

int main ()
{
  struct list l = { '1' };
  ERI_LST_INIT_LIST (x, &l);
  struct node n[6];
  int i;
  for (i = 0; i < sizeof n / sizeof n[0]; ++i)
    {
      n[i].a = i;
      n[i].b = (char) i;
      x_append (&l, n + i);
    }

  struct node *it;
  ERI_LST_FOREACH (x, &l, it)
    eri_assert (eri_printf ("%u %u\n", it->a, it->b) == 0);
  eri_assert (eri_printf ("\n") == 0);

  for (i = 0; i < sizeof n / sizeof n[0]; ++i)
    {
      x_remove (n + (i % 2 == 0 ? i + 1 : i - 1));
      ERI_LST_FOREACH (x, &l, it)
        eri_assert (eri_printf ("%u %u\n", it->a, it->b) == 0);
      eri_assert (eri_printf ("\n") == 0);
    }

  return 0;
}
