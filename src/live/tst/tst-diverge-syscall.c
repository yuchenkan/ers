#define ERI_APPLY_ERS

#include <lib/util.h>
#include <lib/syscall-common.h>
#include <live/tst/tst-diverge.h>

TST_LIVE_DIVERGE_DEFINE_TST (3,
  asm ("syscall" : : "ax" (__NR_sched_yield) : "r11", "cx"), 0, 0, 0)
