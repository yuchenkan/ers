#include <stdint.h>

#include "tst/tst-live-quit-common.h"

static void
start_child (void *data)
{
  TST_LIVE_QUIT_YIELD;

  if ((uint64_t) data % 2 == 0)
    tst_live_quit_exit (0);
  else
    tst_live_quit_exit_group (0);
}

static struct tst_live_quit_child children[8];
void
tst_live_quit_main (void)
{
  uint64_t i;
  for (i = 0; i < eri_length_of (children); ++i)
    tst_live_quit_clone (children + i, start_child, (void *) i);

  TST_LIVE_QUIT_YIELD;
  tst_live_quit_exit_group (0);
}
