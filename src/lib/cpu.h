#ifndef ERI_LIB_CPU_H
#define ERI_LIB_CPU_H

#include <lib/util.h>

#define _ERI_R0_b(i)		ERI_PASTE (i, l)
#define _ERI_R0_w(i)		ERI_PASTE (i, x)
#define _ERI_R0_l(i)		ERI_PASTE2 (e, i, x)
#define _ERI_R0_q(i)		ERI_PASTE2 (r, i, x)

#define ERI_RAX(sz)		ERI_PASTE (_ERI_R0_, sz) (a)
#define ERI_RBX(sz)		ERI_PASTE (_ERI_R0_, sz) (b)
#define ERI_RDX(sz)		ERI_PASTE (_ERI_R0_, sz) (d)
#define ERI_RCX(sz)		ERI_PASTE (_ERI_R0_, sz) (c)

#define _ERI_R1_b(i)		ERI_PASTE (i, l)
#define _ERI_R1_w(i)		i
#define _ERI_R1_l(i)		ERI_PASTE (e, i)
#define _ERI_R1_q(i)		ERI_PASTE (r, i)

#define ERI_RDI(sz)		ERI_PASTE (_ERI_R1_, sz) (di)
#define ERI_RSI(sz)		ERI_PASTE (_ERI_R1_, sz) (si)
#define ERI_RSP(sz)		ERI_PASTE (_ERI_R1_, sz) (sp)
#define ERI_RBP(sz)		ERI_PASTE (_ERI_R1_, sz) (bp)

#define _ERI_R2_b(i)		ERI_PASTE (i, b)
#define _ERI_R2_w(i)		ERI_PASTE (i, w)
#define _ERI_R2_l(i)		ERI_PASTE (i, d)
#define _ERI_R2_q(i)		i

#define ERI_R8(sz)		ERI_PASTE (_ERI_R2_, sz) (r8)
#define ERI_R9(sz)		ERI_PASTE (_ERI_R2_, sz) (r9)
#define ERI_R10(sz)		ERI_PASTE (_ERI_R2_, sz) (r10)
#define ERI_R11(sz)		ERI_PASTE (_ERI_R2_, sz) (r11)
#define ERI_R12(sz)		ERI_PASTE (_ERI_R2_, sz) (r12)
#define ERI_R13(sz)		ERI_PASTE (_ERI_R2_, sz) (r13)
#define ERI_R14(sz)		ERI_PASTE (_ERI_R2_, sz) (r14)
#define ERI_R15(sz)		ERI_PASTE (_ERI_R2_, sz) (r15)

#define ERI_FOREACH_REG_SIZE3(p, ...) \
  p (b, ##__VA_ARGS__)							\
  p (w, ##__VA_ARGS__)							\
  p (l, ##__VA_ARGS__)

#define ERI_FOREACH_REG_SIZE(p, ...) \
  ERI_FOREACH_REG_SIZE3 (p, ##__VA_ARGS__)				\
  p (q, ##__VA_ARGS__)

#define ERI_RFLAGS_ZERO_BIT_OFFSET	6
#define ERI_RFLAGS_TRACE_BIT_OFFSET	8

#define ERI_RFLAGS_ZERO_MASK		(1 << ERI_RFLAGS_ZERO_BIT_OFFSET)
#define ERI_RFLAGS_TRACE_MASK		(1 << ERI_RFLAGS_TRACE_BIT_OFFSET)

#endif
