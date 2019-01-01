#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "lib/tst/tst-util.h"

#include "lib/printf.h"

static void
start_child (void *data)
{
  TST_YIELD (32);

  if ((uint64_t) data % 2 == 0)
    tst_live_quit_exit (0);
  else
    tst_live_quit_exit_group (0);
}

static struct tst_live_quit_child children[8];

void
tst_live_quit_main (void)
{
  eri_assert_printf ("main\n");
  tst_live_quit_allow_clone = 1;
  tst_live_quit_allow_group = 1;

  uint64_t i;
  for (i = 0; i < eri_length_of (children); ++i)
    tst_live_quit_clone_child (children + i, start_child, (void *) i);

  TST_YIELD (32);
  tst_live_quit_exit_group (0);
}
