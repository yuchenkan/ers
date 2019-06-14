/* vim: set ft=cpp: */

#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/util.h>

#include <tst/tst-syscall.h>
#include <tst/tst-atomic.h>

#include <live/tst/tst-diverge.h>

static uint32_t val;

TST_LIVE_DIVERGE_DEFINE_TST (3, ERI_EVAL (do {
  if (diverge) tst_assert_syscall (sched_yield);
  else tst_atomic_inc (&val, 0);
} while (0)), 0, 0, 0)
