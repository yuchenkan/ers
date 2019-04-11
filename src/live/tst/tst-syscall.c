#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static eri_noreturn void
start_raise (struct tst_sys_clone_raise_args *args)
{
  tst_yield (args->delay);
  uint32_t back = 1, i;
  for (i = 0; i < args->count || args->count == 0; ++i)
    {
      tst_assert_syscall (tgkill, args->pid, args->tid, args->sig);
      tst_yield ((back *= 2) / 64);
    }
  tst_assert_sys_exit (0);
}

void
tst_assert_sys_clone_raise (struct tst_sys_clone_raise_args *args)
{
  struct eri_sys_clone_args clone_args = {
    ERI_CLONE_SUPPORTED_FLAGS, args->top, 0, &args->alive, 0,
    start_raise, args
  };
  tst_assert_sys_clone (&clone_args);
}

static eri_noreturn void
start_exit_group (struct tst_sys_clone_exit_group_args *args)
{
  tst_yield (args->delay);
  tst_assert_sys_exit_group (0);
}

void
tst_assert_sys_clone_exit_group (struct tst_sys_clone_exit_group_args *args)
{
  struct eri_sys_clone_args clone_args = {
    ERI_CLONE_SUPPORTED_FLAGS, args->top, 0, 0, 0,
    start_exit_group, args
  };
  tst_assert_sys_clone (&clone_args);
}
