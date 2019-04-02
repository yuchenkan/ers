#include <lib/compiler.h>
#include <lib/syscall.h>

#include <replay/thread.h>

eri_noreturn void
tst_main (void **args)
{
  /* TODO */ (void) eri_replay_start;
  eri_assert_sys_exit (0);
}
