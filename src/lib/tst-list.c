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
  for (i = 0; i < eri_length_of (n); ++i)
    {
      n[i].a = i;
      n[i].b = (char) i;
      x_lst_append (&l, n + i);
    }

  struct node *it;
  ERI_LST_FOREACH (x, &l, it)
    eri_assert_printf ("%u %u\n", it->a, it->b);
  eri_assert_printf ("\n");

  for (i = 0; i < eri_length_of (n); ++i)
    {
      x_lst_remove (&l, n + (i % 2 == 0 ? i + 1 : i - 1));
      ERI_LST_FOREACH (x, &l, it)
	eri_assert_printf ("%u %u\n", it->a, it->b);
      eri_assert_printf ("\n");
    }

  return 0;
}
