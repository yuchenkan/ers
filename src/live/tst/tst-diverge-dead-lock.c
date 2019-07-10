/* vim: set ft=cpp: */

#include <public/public.h>
#define ERI_APPLY_ERS

#include <tst/tst-atomic.h>
#include <live/tst/tst-diverge.h>

static uint32_t a, b;

TST_LIVE_DIVERGE_DEFINE_TST (4, ERI_EVAL (do {
  tst_atomic_inc (&a, 1);
  tst_yield (4);
  tst_atomic_inc (diverge ? &b : &a, 1);
} while (0)), 0, 0, 0)
