#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "lib/printf.h"
#include "lib/syscall.h"

static void
child (void *data)
{
  eri_assert ((uint64_t) data == 0xff);
  TST_LIVE_QUIT_YIELD;
  eri_assert_lprintf (&tst_live_quit_printf_lock, "child\n");
  tst_live_quit_exit (0);
}

static uint8_t stack[TST_LIVE_QUIT_STACK_SIZE];
static int32_t ptid;
static int32_t ctid;

uint64_t
tst_live_quit_main (void)
{
  eri_assert_printf ("main\n");
  tst_live_quit_clone (stack, &ptid, &ctid, child, (void *) 0xff);
  TST_LIVE_QUIT_YIELD;
  tst_live_quit_exit (0);
}
