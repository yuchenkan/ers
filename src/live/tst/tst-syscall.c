#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static eri_noreturn void
start (struct tst_live_clone_args *args)
{
  tst_yield (args->delay);
  if (args->fn) args->fn (args->args);
  tst_assert_sys_exit (0);
}

void
tst_assert_live_clone (struct tst_live_clone_args *args)
{
  args->alive = 1;
  struct eri_sys_clone_args clone_args = {
    ERI_CLONE_SUPPORTED_FLAGS, args->top, 0, &args->alive, 0,
    start, args
  };
  tst_assert_sys_clone (&clone_args);
}

static void
raise (struct tst_live_clone_raise_args *args)
{
  uint32_t back = 1, i;
  for (i = 0; i < args->count || args->count == 0; ++i)
    {
      tst_assert_syscall (tgkill, args->pid, args->tid, args->sig);
      tst_yield ((back *= 2) / 64);
    }
}

void
tst_assert_live_clone_raise (struct tst_live_clone_raise_args *args)
{
  if (! args->sig) args->sig = ERI_SIGINT;
  if (! args->pid) args->pid = tst_assert_syscall (getpid);
  if (! args->tid) args->tid = tst_assert_syscall (gettid);

  args->args.fn = (void *) raise;
  args->args.args = args;
  tst_assert_live_clone (&args->args);
}

static eri_noreturn void
exit_group (void *args)
{
  tst_assert_sys_exit_group (0);
}

void
tst_assert_live_clone_exit_group (struct tst_live_clone_args *args)
{
  args->fn = exit_group;
  tst_assert_live_clone (args);
}
