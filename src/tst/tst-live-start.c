#include <stdint.h>

#include <compiler.h>

#include <live-signal-thread.h>
#include <common.h>

#include <tst/tst-recorder.h>

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  eri_debug ("\n");
  tst_syscall (exit, 0);
  eri_assert_unreachable ();
}
