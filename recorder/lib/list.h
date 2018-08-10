#ifndef ERS_LIST_H
#define ERS_LIST_H

#define ERS_INIT_LIST(pfx, list) \
  do { typeof (list) __ers_l = (list);						\
       __ers_l->pfx##_list[0] = __ers_l->pfx##_list[1] = __ers_l->pfx##_list; } while (0)
#define ERS_LIST_FIELDS(pfx) void *pfx##_list[2];
#define ERS_NODE_FIELDS(pfx) void *pfx##_list[2];

#define ERS_DECLARE_LIST(attr, pfx, list_type, node_type) \
attr __attribute__ ((used)) void pfx##_append (list_type *list, node_type *node);	\
attr __attribute__ ((used)) void pfx##_remove (node_type *node);

#define ERS_DEFINE_LIST(attr, pfx, list_type, node_type) \
static void									\
pfx##_insert_after (void **n, void **nn)					\
{										\
  nn[0] = n;			/* nn->prev = n; */				\
  nn[1] = n[1];			/* nn->next = n->next; */			\
  ((void **) n[1])[0] = nn;	/* n->next->prev = nn; */			\
  n[1] = nn;			/* n->next = nn; */				\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_append (list_type *list, node_type *node)					\
{										\
  pfx##_insert_after ((void **) list->pfx##_list[0], node->pfx##_list);		\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_remove (node_type *node)							\
{										\
  void **n = node->pfx##_list;							\
  ((void **) n[0])[1] = n[1];	/* n->prev->next = n->next; */			\
  ((void **) n[1])[0] = n[0];	/* n->next->prev = n->prev; */			\
}

#define ERS_LIST_FOREACH(pfx, list, iter) \
  for (iter = (typeof (iter)) (list)->pfx##_list[1];				\
       iter != (typeof (iter)) (list)->pfx##_list				\
       && (iter = (typeof (iter)) ((char *) iter - __builtin_offsetof (typeof (*iter), pfx##_list)));	\
       iter = (typeof (iter)) iter->pfx##_list[1])

#endif
