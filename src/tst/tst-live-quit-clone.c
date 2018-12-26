#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "lib/printf.h"

static void
start_child (void *data)
{
  eri_assert ((uint64_t) data == 0xff);
  TST_LIVE_QUIT_YIELD;
  eri_assert_lprintf (&tst_live_quit_printf_lock, "child\n");
  tst_live_quit_exit (0);
}

static struct tst_live_quit_child child;

void
tst_live_quit_main (void)
{
  eri_assert_printf ("main\n");
  tst_live_quit_clone (&child, start_child, (void *) 0xff);
  TST_LIVE_QUIT_YIELD;
  tst_live_quit_exit (0);
}
