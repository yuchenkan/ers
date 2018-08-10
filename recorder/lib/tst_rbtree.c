#include "util.h"
#include "rbtree.h"
#include "printf.h"

struct tree
{
  char a;
  ERS_RBT_TREE_FIELDS (x, struct node)
};

struct node
{
  int k;
  char v;
  ERS_RBT_NODE_FIELDS (x, struct node)
};

ERS_DECALRE_RBTREE(static, x, struct tree, struct node, int)

#define x_less_than(x, a, b) (*(a) < *(b))
ERS_DEFINE_RBTREE(static, x, struct tree, struct node, int, x_less_than)

int main()
{
  struct tree t = { 0 };
  ERS_RBT_INIT_TREE (x, &t);

  struct node n[6];
  int i;
  for (i = 0; i < sizeof n / sizeof n[0]; ++i)
    {
      n[i].k = 2 * i;
      n[i].v = (char) i;
    }

  x_insert (&t, n + 3);
  x_insert (&t, n + 2);
  x_insert (&t, n + 5);
  x_insert (&t, n + 4);
  x_insert (&t, n + 0);
  x_insert (&t, n + 1);

  struct node *it;
  ERS_RBT_FOREACH (x, &t, it)
    ers_assert (ers_printf ("%u %u\n", it->k, it->v) == 0);
  ers_assert (ers_printf ("\n") == 0);

  int k;
  ers_assert (x_get (&t, (k = 0, &k), ERS_RBT_EQ) == n + 0);
  ers_assert (x_get (&t, (k = 6, &k), ERS_RBT_EQ) == n + 3);
  ers_assert (x_get (&t, (k = 10, &k), ERS_RBT_EQ) == n + 5);
  ers_assert (x_get (&t, (k = 5, &k), ERS_RBT_EQ) == NULL);
  ers_assert (x_get (&t, (k = 5, &k), ERS_RBT_GT) == n + 3);
  ers_assert (x_get (&t, (k = 9, &k), ERS_RBT_GT) == n + 5);
  ers_assert (x_get (&t, (k = 10, &k), ERS_RBT_GT) == NULL);
  ers_assert (x_get (&t, (k = 10, &k), ERS_RBT_EQ | ERS_RBT_GT) == n + 5);
  ers_assert (x_get (&t, (k = 1, &k), ERS_RBT_EQ | ERS_RBT_GT) == n + 1);
  ers_assert (x_get (&t, (k = 3, &k), ERS_RBT_EQ | ERS_RBT_LT) == n + 1);
  ers_assert (x_get (&t, (k = 4, &k), ERS_RBT_EQ | ERS_RBT_LT) == n + 2);
  ers_assert (x_get (&t, (k = 4, &k), ERS_RBT_LT) == n + 1);

  x_remove (&t, n + 3);
  ers_assert (x_get_first (&t) == n + 0);
  ERS_RBT_FOREACH (x, &t, it)
    ers_assert (ers_printf ("%u %u\n", it->k, it->v) == 0);
  ers_assert (ers_printf ("\n") == 0);
  x_remove (&t, n + 2);
  ers_assert (x_get_first (&t) == n + 0);
  ERS_RBT_FOREACH (x, &t, it)
    ers_assert (ers_printf ("%u %u\n", it->k, it->v) == 0);
  ers_assert (ers_printf ("\n") == 0);
  x_remove (&t, n + 1);
  ers_assert (x_get_first (&t) == n + 0);
  ERS_RBT_FOREACH (x, &t, it)
    ers_assert (ers_printf ("%u %u\n", it->k, it->v) == 0);
  ers_assert (ers_printf ("\n") == 0);
  x_remove (&t, n + 0);
  ers_assert (x_get_first (&t) == n + 4);
  ERS_RBT_FOREACH (x, &t, it)
    ers_assert (ers_printf ("%u %u\n", it->k, it->v) == 0);
  ers_assert (ers_printf ("\n") == 0);
  x_remove (&t, n + 4);
  ers_assert (x_get_first (&t) == n + 5);
  ERS_RBT_FOREACH (x, &t, it)
    ers_assert (ers_printf ("%u %u\n", it->k, it->v) == 0);
  ers_assert (ers_printf ("\n") == 0);
  x_remove (&t, n + 5);
  ers_assert (x_get_first (&t) == NULL);
  ERS_RBT_FOREACH (x, &t, it)
    ers_assert (ers_printf ("%u %u\n", it->k, it->v) == 0);
  ers_assert (ers_printf ("\n") == 0);
  return 0;
}
