#ifndef TST_LIVE_TST_TST_UTIL_H
#define TST_LIVE_TST_TST_UTIL_H

#include <lib/util.h>
#include <lib/cpu.h>

#define tst_get_tls() \
  ({ void *_tls; asm ("movq\t%%fs:0, %0" : "=r" (_tls)); _tls; })

#define TST_UNUSED(func) \
  asm (ERI_STR (ERI_SYMBOL (func)) ERI_STR (ERI_ASSERT_FALSE));

#define TST_WEAK_SYMBOL(symbol) \
  .global symbol;							\
  .weak symbol;								\
  .hidden symbol;							\
symbol:

#define TST_WEAK_BLANK_ZERO(func) \
asm (ERI_STR (TST_WEAK_SYMBOL (func)) "xorq	%rax, %rax; ret");

#define TST_WEAK_BLANK(func) \
asm (ERI_STR (TST_WEAK_SYMBOL (func)) "ret");

#define tst_enable_trace() \
asm ("pushq\t%0; popfq" : : "n" (ERI_RFLAGS_TF) : "cc", "memory");

#define tst_disable_trace() \
asm ("pushq\t$0; popfq" : : : "cc", "memory");

#endif
