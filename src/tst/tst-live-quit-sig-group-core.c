#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "lib/tst/tst-util.h"

#include "lib/syscall.h"
#include "lib/printf.h"

static void
start_child (void *data)
{
  TST_YIELD (32);
  *(uint8_t *) 0 = 0;
}

void
tst_live_sig_final_quit (int32_t sig)
{
  eri_assert_printf ("[tst_live_sig_final_quit]\n");

  eri_assert (sig == ERI_SIGSEGV);

  ERI_ASSERT_SYSCALL (exit_group, 0);
}

static struct tst_live_quit_child children[4];

void
tst_live_quit_main (void)
{
  eri_assert_printf ("main\n");
  tst_live_quit_allow_clone = 1;
  tst_live_quit_allow_group = ERI_SIGSEGV;

  uint64_t i;
  for (i = 0; i < eri_length_of (children); ++i)
    tst_live_quit_clone_child (children + i, start_child, (void *) i);

  TST_YIELD (32);

  while (1) TST_YIELD (32);
}
