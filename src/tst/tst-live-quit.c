#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "live.h"
#include "live-entry.h"

#include "lib/printf.h"
#include "lib/syscall.h"

uint64_t
tst_live_quit_main (void)
{
  eri_assert_printf ("main\n");
  tst_live_quit_exit (0);
}
