#include <tst/tst-syscall.h>
#include <tst/tst-syscall-dedicated.c>

#include <tst/tst-util.h>

static noreturn void start_raise (struct tst_sys_clone_raise_args *args);

static noreturn void
start_raise (struct tst_sys_clone_raise_args *args)
{
  tst_yield (args->delay);
  tst_assert_syscall (tgkill, args->pid, args->tid, args->sig);
  tst_assert_sys_exit (0);
}

void
tst_assert_sys_clone_raise (struct tst_sys_clone_raise_args *args)
{
  struct eri_sys_clone_args clone_args = {
    ERI_CLONE_SUPPORTED_FLAGS, args->top, 0, 0, 0,
    start_raise, args
  };
  tst_assert_sys_clone (&clone_args);
}
