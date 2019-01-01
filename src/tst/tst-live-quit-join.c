#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "lib/tst/tst-util.h"

#include "lib/printf.h"
#include "lib/lock.h"
#include "lib/syscall.h"

static int32_t ctid;

static void
start_child (void *data)
{
  ctid = ERI_ASSERT_SYSCALL_RES (gettid);

  TST_YIELD (32);
  eri_assert_lprintf (&tst_live_quit_printf_lock, "child\n");
  tst_live_quit_exit (0);
}

static struct tst_live_quit_child child = { 1 };

void
tst_live_quit_main (void)
{
  eri_assert_printf ("main\n");
  tst_live_quit_allow_clone = 1;

  tst_live_quit_clone_child (&child, start_child, 0);
  TST_YIELD (32);
  eri_lock (&child.ctid);
  eri_assert (ctid == child.ptid);

  tst_live_quit_exit_group (0);
}
