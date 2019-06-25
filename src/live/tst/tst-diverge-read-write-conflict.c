/* vim: set ft=cpp: */

#include <public/public.h>
#define ERI_APPLY_ERS

#include <common/debug.h>
#include <tst/tst-atomic.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-diverge.h>

static uint8_t a;

#define NTH	4
static uint8_t n = NTH;

TST_LIVE_DIVERGE_DEFINE_TST (NTH, ERI_EVAL (do {
  uint64_t i = (uint64_t) args;
  if (i == 1) eri_info ("%lx\n", &a);
  tst_atomic_dec (&n, 0);
  while (tst_atomic_load (&n, 1)) tst_yield (1);
  if (i % 2) asm ("testb\t$0, %0" : : "m" (a) : "cc", "memory");
  else asm ("movb\t$0, %0" : "=m" (a) : : "memory");
} while (0)), 1, 0, 0)
