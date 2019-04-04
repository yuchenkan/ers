#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/syscall.h>

#include <common/common.h>
#include <replay/rtld.h>

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *rtld_args)
{
  /* const char *conf = rtld_args->path + eri_strlen (rtld_args->path) + 1; */

  eri_info ("start\n");
  eri_assert_sys_exit (0);
}
