#ifndef ERI_LIB_ATOMIC_COMMON_H
#define ERI_LIB_ATOMIC_COMMON_H

#include <lib/util.h>

#define eri_barrier()			asm ("" : : : "memory")

#define _ERI_ASM_TEMPLATE_SIZE_b	b
#define _ERI_ASM_TEMPLATE_SIZE_w	w
#define _ERI_ASM_TEMPLATE_SIZE_l	k
#define _ERI_ASM_TEMPLATE_SIZE_q	q
#define _ERI_ASM_TEMPLATE_SIZE(sz, i) \
  ERI_PASTE (ERI_PASTE (_ERI_ASM_TEMPLATE_SIZE_, sz), i)

#define _eri_atomic_switch_size(_m, op, ...) \
  do {									\
    if (sizeof *_m == 1) op (b, _m, ##__VA_ARGS__);			\
    else if (sizeof *_m == 2) op (w, _m, ##__VA_ARGS__);		\
    else if (sizeof *_m == 4) op (l, _m, ##__VA_ARGS__);		\
    else if (sizeof *_m == 8) op (q, _m, ##__VA_ARGS__);		\
    else eri_assert_unreachable ();					\
  } while (0)

#define _eri_atomic_switch_size1(_m, op, ...) \
  do {									\
    if (sizeof *_m == 2) op (w, _m, ##__VA_ARGS__);			\
    else if (sizeof *_m == 4) op (l, _m, ##__VA_ARGS__);		\
    else if (sizeof *_m == 8) op (q, _m, ##__VA_ARGS__);		\
    else eri_assert_unreachable ();					\
  } while (0)

#endif
