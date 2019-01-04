#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "lib/tst/tst-util.h"

#include "lib/syscall.h"
#include "lib/printf.h"

static void
start_child (void *data)
{
  while (1) TST_YIELD (32);
}

static int32_t pid, tid;

void
tst_live_sig_final_quit (int32_t sig)
{
  eri_assert_printf ("[tst_live_sig_final_quit]\n");

  eri_assert (sig == ERI_SIGINT);
  eri_assert (tid == ERI_ASSERT_SYSCALL_RES (gettid));

  ERI_ASSERT_SYSCALL (exit_group, 0);
}

static struct tst_live_quit_child children[4];

void
tst_live_quit_main (void)
{
  eri_assert_printf ("main\n");
  tst_live_quit_allow_clone = 1;
  tst_live_quit_allow_group = ERI_SIGINT;

  uint64_t i;
  for (i = 0; i < eri_length_of (children); ++i)
    tst_live_quit_clone_child (children + i, start_child, (void *) i);

  TST_YIELD (32);
  pid = ERI_ASSERT_SYSCALL_RES (getpid);
  tid = ERI_ASSERT_SYSCALL_RES (gettid);
  ERI_ASSERT_SYSCALL (tgkill, pid, tid, ERI_SIGINT);

  while (1) TST_YIELD (32);
}
