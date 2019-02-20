#include <stdint.h>

#include <lib/util.h>
#include <lib/rbtree.h>
#include <lib/printf.h>

struct node
{
  int32_t k;
  uint8_t v;
  ERI_RBT_NODE_FIELDS (x, struct node)
};

struct tree
{
  uint8_t a;
  ERI_RBT_TREE_FIELDS (x, struct node)
};

ERI_DECLARE_RBTREE (static, x, struct tree, struct node, int32_t)

#define x_rbt_less_than(x, a, b)	(*(a) < *(b))
ERI_DEFINE_RBTREE (static, x, struct tree, struct node,
		   int32_t, x_rbt_less_than)

int32_t
main (void)
{
  struct tree t = { 0 };
  ERI_RBT_INIT_TREE (x, &t);

  struct node n[6];
  int32_t i;
  for (i = 0; i < eri_length_of (n); ++i)
    {
      n[i].k = 2 * i;
      n[i].v = (uint8_t) i;
    }

  x_rbt_insert (&t, n + 3);
  x_rbt_insert (&t, n + 2);
  x_rbt_insert (&t, n + 5);
  x_rbt_insert (&t, n + 4);
  x_rbt_insert (&t, n + 0);
  x_rbt_insert (&t, n + 1);

  struct node *it;
  ERI_RBT_FOREACH (x, &t, it)
    eri_assert_printf ("%u %u\n", it->k, it->v);
  eri_assert_printf ("\n");

  int32_t k;
  eri_assert (x_rbt_get (&t, (k = 0, &k), ERI_RBT_EQ) == n + 0);
  eri_assert (x_rbt_get (&t, (k = 6, &k), ERI_RBT_EQ) == n + 3);
  eri_assert (x_rbt_get (&t, (k = 10, &k), ERI_RBT_EQ) == n + 5);
  eri_assert (x_rbt_get (&t, (k = 5, &k), ERI_RBT_EQ) == 0);
  eri_assert (x_rbt_get (&t, (k = 5, &k), ERI_RBT_GT) == n + 3);
  eri_assert (x_rbt_get (&t, (k = 9, &k), ERI_RBT_GT) == n + 5);
  eri_assert (x_rbt_get (&t, (k = 10, &k), ERI_RBT_GT) == 0);
  eri_assert (x_rbt_get (&t, (k = 10, &k), ERI_RBT_EQ | ERI_RBT_GT) == n + 5);
  eri_assert (x_rbt_get (&t, (k = 1, &k), ERI_RBT_EQ | ERI_RBT_GT) == n + 1);
  eri_assert (x_rbt_get (&t, (k = 3, &k), ERI_RBT_EQ | ERI_RBT_LT) == n + 1);
  eri_assert (x_rbt_get (&t, (k = 4, &k), ERI_RBT_EQ | ERI_RBT_LT) == n + 2);
  eri_assert (x_rbt_get (&t, (k = 4, &k), ERI_RBT_LT) == n + 1);

  x_rbt_remove (&t, n + 3);
  eri_assert (x_rbt_get_first (&t) == n + 0);
  ERI_RBT_FOREACH (x, &t, it)
    eri_assert_printf ("%u %u\n", it->k, it->v);
  eri_assert_printf ("\n");
  x_rbt_remove (&t, n + 2);
  eri_assert (x_rbt_get_first (&t) == n + 0);
  ERI_RBT_FOREACH (x, &t, it)
    eri_assert_printf ("%u %u\n", it->k, it->v);
  eri_assert_printf ("\n");
  x_rbt_remove (&t, n + 1);
  eri_assert (x_rbt_get_first (&t) == n + 0);
  ERI_RBT_FOREACH (x, &t, it)
    eri_assert_printf ("%u %u\n", it->k, it->v);
  eri_assert_printf ("\n");
  x_rbt_remove (&t, n + 0);
  eri_assert (x_rbt_get_first (&t) == n + 4);
  ERI_RBT_FOREACH (x, &t, it)
    eri_assert_printf ("%u %u\n", it->k, it->v);
  eri_assert_printf ("\n");
  x_rbt_remove (&t, n + 4);
  eri_assert (x_rbt_get_first (&t) == n + 5);
  ERI_RBT_FOREACH (x, &t, it)
    eri_assert_printf ("%u %u\n", it->k, it->v);
  eri_assert_printf ("\n");
  x_rbt_remove (&t, n + 5);
  eri_assert (x_rbt_get_first (&t) == 0);
  ERI_RBT_FOREACH (x, &t, it)
    eri_assert_printf ("%u %u\n", it->k, it->v);
  eri_assert_printf ("\n");
  return 0;
}
