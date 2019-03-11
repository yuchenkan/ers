#include <lib/printf.h>

#include <replay/rtld.h>
#include <replay/thread.h>

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *args)
{
  eri_assert_printf ("eri_replay_start\n");
  while (1) continue;
}
