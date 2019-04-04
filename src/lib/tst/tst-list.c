#include <lib/util.h>
#include <lib/list.h>
#include <lib/printf.h>

struct node
{
  int32_t a;
  int8_t b;
  ERI_LST_NODE_FIELDS (x);
};

struct list
{
  int8_t a;
  ERI_LST_LIST_FIELDS (x);
};

ERI_DECLARE_LIST (static, x, struct list, struct node)
ERI_DEFINE_LIST (static, x, struct list, struct node)

int32_t
main (void)
{
  struct list l = { '1' };
  ERI_LST_INIT_LIST (x, &l);
  struct node n[6];
  int32_t i;
  for (i = 0; i < eri_length_of (n); ++i)
    {
      n[i].a = i;
      n[i].b = (int8_t) i;
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

  for (i = 0; i < eri_length_of (n); ++i)
    x_lst_insert_front (&l, n + i);

  ERI_LST_FOREACH (x, &l, it)
    eri_assert_printf ("%u %u\n", it->a, it->b);
  eri_assert_printf ("\n");

  return 0;
}
