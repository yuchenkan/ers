#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "lib/atomic.h"

static void
start_child (void *data)
{
  tst_live_quit_exit (0);
}

static int32_t ptid;
static uint8_t stack[TST_LIVE_QUIT_STACK_SIZE];

void
tst_live_quit_main (void)
{
  tst_live_quit_clone (stack, &ptid, 0, start_child, 0);
  while (tst_live_quit_multi_threading ()) continue;
  eri_barrier ();
  tst_live_quit_exit (0);
}
