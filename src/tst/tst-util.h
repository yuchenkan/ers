#ifndef ERI_TST_TST_UTIL_H
#define ERI_TST_TST_UTIL_H

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

#endif
