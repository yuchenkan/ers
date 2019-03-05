#ifndef TST_LIVE_TST_TST_UTIL_H
#define TST_LIVE_TST_TST_UTIL_H

#include <lib/util.h>
#include <lib/syscall.h>

#define tst_yield(n) \
  do {									\
    typeof (n) _i;							\
    typeof (n) _n = n;							\
    for (_i = 0; _i < _n; ++_i) eri_assert_syscall (sched_yield);	\
  } while (0)

#define tst_get_tls() \
  ({ void *_tls; asm ("movq	%%fs:0, %0" : "=r" (_tls)); _tls; })

#define TST_RFLAGS_TRACE_BIT_OFFSET	8
#define TST_RFLAGS_TRACE_MASK		(1 << TST_RFLAGS_TRACE_BIT_OFFSET)

/* XXX: check other flags */
#define TST_RFLAGS_STATUS_MASK		0xd5

#define TST_UNUSED(func) \
  asm (ERI_STR (ERI_SYMBOL (func)) ERI_STR (ERI_ASSERT_FALSE));

#define TST_WEAK_SYMBOL(symbol) \
  .global symbol;							\
  .weak symbol;								\
  .hidden symbol;							\
symbol:

#define TST_WEAK_BLANK_ZERO(func) \
asm (ERI_STR (TST_WEAK_SYMBOL (func)) "xorq	%rax, %rax; ret")

#define TST_WEAK_BLANK(func) \
asm (ERI_STR (TST_WEAK_SYMBOL (func)) "ret")

#define tst_enable_trace() \
asm ("pushq	%0; popfq" : : "n" (TST_RFLAGS_TRACE_MASK) : "cc", "memory");

#define tst_struct(mem, st, name) \
  ((void *) ((uint64_t) mem - __builtin_offsetof (st, name)))

#endif
