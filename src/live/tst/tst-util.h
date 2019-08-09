#ifndef TST_LIVE_TST_TST_UTIL_H
#define TST_LIVE_TST_TST_UTIL_H

#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/elf.h>

#include <tst/tst-atomic.h>

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

#define tst_get_plain(args) \
  ({ void *_a = args;							\
     uint64_t _r = 0;							\
     if (_a)								\
       {								\
	 char **_p;							\
	 for (_p = eri_get_envp_from_args (_a); *_p; ++_p)		\
	   eri_get_arg_int (*_p, "TST_PLAIN=", &_r, 10);		\
       }								\
     !! _r; })

static eri_unused void
tst_check (uint64_t v)
{
  uint8_t x = 0, i;
  for (i = 0; i < eri_hash (v) % 16; ++i)
    tst_atomic_inc (&x, 1);
}

#endif
