#ifndef ERI_LIST_H
#define ERI_LIST_H

#define ERI_LST_INIT_LIST(pfx, list) \
  do { typeof (list) __eri_l = (list);						\
       __eri_l->pfx##_lst[0] = __eri_l->pfx##_lst[1] = __eri_l->pfx##_lst; } while (0)
#define ERI_LST_LIST_FIELDS(pfx) void *pfx##_lst[2];
#define ERI_LST_NODE_FIELDS(pfx) void *pfx##_lst[2];

#define ERI_DECLARE_LIST(attr, pfx, list_type, node_type) \
attr __attribute__ ((used)) void pfx##_lst_append (list_type *list, node_type *node);	\
attr __attribute__ ((used)) void pfx##_lst_remove (node_type *node);

#define ERI_DEFINE_LIST(attr, pfx, list_type, node_type) \
static void									\
pfx##_lst_insert_after (void **n, void **nn)					\
{										\
  nn[0] = n;			/* nn->prev = n; */				\
  nn[1] = n[1];			/* nn->next = n->next; */			\
  ((void **) n[1])[0] = nn;	/* n->next->prev = nn; */			\
  n[1] = nn;			/* n->next = nn; */				\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_lst_append (list_type *list, node_type *node)				\
{										\
  pfx##_lst_insert_after ((void **) list->pfx##_lst[0], node->pfx##_lst);	\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_lst_remove (node_type *node)						\
{										\
  void **n = node->pfx##_lst;							\
  ((void **) n[0])[1] = n[1];	/* n->prev->next = n->next; */			\
  ((void **) n[1])[0] = n[0];	/* n->next->prev = n->prev; */			\
}

#define ERI_LST_FOREACH(pfx, list, iter) \
  for (iter = (typeof (iter)) (list)->pfx##_lst[1];				\
       iter != (typeof (iter)) (list)->pfx##_lst				\
       && (iter = (typeof (iter)) ((char *) iter - __builtin_offsetof (typeof (*iter), pfx##_lst)));	\
       iter = (typeof (iter)) iter->pfx##_lst[1])

#define ERI_LST_FOREACH_SAFE(pfx, list, iter, next) \
  for (iter = (typeof (iter)) (list)->pfx##_lst[1];				\
       iter != (typeof (iter)) (list)->pfx##_lst				\
       && (iter = (typeof (iter)) ((char *) iter - __builtin_offsetof (typeof (*iter), pfx##_lst)))	\
       && ({ next = (typeof (iter)) iter->pfx##_lst[1]; 1; });			\
       iter = next)


#endif
