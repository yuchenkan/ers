#ifndef ERI_LIB_LIST_H
#define ERI_LIB_LIST_H

#include <stdint.h>

#include <lib/compiler.h>

#define ERI_LST_INIT_LIST(pfx, list) \
  do { typeof (list) _list = list;					\
       _list->ERI_PASTE (pfx, _lst)[0]					\
		= _list->ERI_PASTE (pfx, _lst)[1]			\
		= _list->ERI_PASTE (pfx, _lst);				\
       _list->ERI_PASTE (pfx, _lst_size) = 0; } while (0)
#define ERI_LST_LIST_FIELDS(pfx) \
  void *ERI_PASTE (pfx, _lst)[2];					\
  uint64_t ERI_PASTE (pfx, _lst_size);
#define ERI_LST_NODE_FIELDS(pfx) void *ERI_PASTE (pfx, _lst)[2];

#define ERI_DECLARE_LIST(attr, pfx, list_type, node_type) \
attr eri_unused void ERI_PASTE (pfx, _lst_insert_front) (		\
				list_type *list, node_type *node);	\
attr eri_unused void ERI_PASTE (pfx, _lst_append) (			\
				list_type *list, node_type *node);	\
attr eri_unused void ERI_PASTE (pfx, _lst_remove) (			\
				list_type *list, node_type *node);	\
attr eri_unused node_type *ERI_PASTE (pfx, _lst_get_first) (		\
				list_type *list);			\
attr eri_unused node_type *ERI_PASTE (pfx, _lst_get_next) (		\
				list_type *list, node_type *node);	\
attr eri_unused uint64_t ERI_PASTE (pfx, _lst_get_size) (list_type *list);

#define ERI_DEFINE_LIST(attr, pfx, list_type, node_type) \
ERI_DECLARE_LIST(attr, pfx, list_type, node_type)			\
									\
static void								\
ERI_PASTE (pfx, _lst_insert_after) (list_type *list,			\
				    void **n, void **nn)		\
{									\
  nn[0] = n;			/* nn->prev = n; */			\
  nn[1] = n[1];			/* nn->next = n->next; */		\
  ((void **) n[1])[0] = nn;	/* n->next->prev = nn; */		\
  n[1] = nn;			/* n->next = nn; */			\
  ++list->ERI_PASTE (pfx, _lst_size);					\
}									\
									\
attr void								\
ERI_PASTE (pfx, _lst_insert_front) (list_type *list, node_type *node)	\
{									\
  ERI_PASTE (pfx, _lst_insert_after) (list,				\
			(void **) list->ERI_PASTE (pfx, _lst),		\
			node->ERI_PASTE (pfx, _lst));			\
}									\
									\
attr void								\
ERI_PASTE (pfx, _lst_append) (list_type *list, node_type *node)		\
{									\
  ERI_PASTE (pfx, _lst_insert_after) (list,				\
			(void **) list->ERI_PASTE (pfx, _lst)[0],	\
			node->ERI_PASTE (pfx, _lst));			\
}									\
									\
attr void								\
ERI_PASTE (pfx, _lst_remove) (list_type *list, node_type *node)		\
{									\
  --list->ERI_PASTE (pfx, _lst_size);					\
  void **n = node->ERI_PASTE (pfx, _lst);				\
  ((void **) n[0])[1] = n[1];	/* n->prev->next = n->next; */		\
  ((void **) n[1])[0] = n[0];	/* n->next->prev = n->prev; */		\
}									\
									\
attr node_type *							\
ERI_PASTE (pfx, _lst_get_first) (list_type *list)			\
{									\
  uint8_t *n = list->ERI_PASTE (pfx, _lst)[1];				\
  return n == (uint8_t *) list->ERI_PASTE (pfx, _lst)			\
	? 0 : (node_type *) (n - __builtin_offsetof (node_type,		\
					ERI_PASTE (pfx, _lst)));	\
}									\
									\
attr node_type *							\
ERI_PASTE (pfx, _lst_get_next) (list_type *list, node_type *node)	\
{									\
  uint8_t *n = node->ERI_PASTE (pfx, _lst)[1];				\
  return n == (uint8_t *) list->ERI_PASTE (pfx, _lst)			\
	? 0 : (node_type *) (n - __builtin_offsetof (node_type,		\
					ERI_PASTE (pfx, _lst)));	\
}									\
									\
attr uint64_t								\
ERI_PASTE (pfx, _lst_get_size) (list_type *list)			\
{									\
  return list->ERI_PASTE (pfx, _lst_size);				\
}

#define ERI_LST_FOREACH(pfx, list, iter) \
  for (iter = ERI_PASTE (pfx, _lst_get_first) (list);			\
       iter; iter = ERI_PASTE (pfx, _lst_get_next) (list, iter))

#define ERI_LST_FOREACH_SAFE(pfx, list, iter, next) \
  for (iter = ERI_PASTE (pfx, _lst_get_first) (list);			\
       iter								\
       && ({ next = ERI_PASTE (pfx, _lst_get_next) (list, iter); 1; });	\
       iter = next)

#endif
