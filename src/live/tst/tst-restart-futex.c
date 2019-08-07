#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-atomic.h>
#include <tst/tst-lock.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static eri_aligned16 uint8_t stack[3][1024 * 1024];
static struct tst_live_clone_args wake_args;
static struct tst_live_clone_raise_args raise_args[2];

static uint8_t hand;

static int32_t futex;
#if 0
static int32_t pipe[2];
#endif

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  tst_atomic_inc (&hand, 0);
  eri_info ("handled %u\n", sig);
}

static void
wake (void *args)
{
  tst_atomic_store (&futex, 1, 1);
  tst_assert_syscall (futex, &futex, ERI_FUTEX_WAKE_PRIVATE, 1);
#if 0
  char buf = 0xab;
  tst_assert_syscall (write, pipe[1], &buf, 1);
#endif
}

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_RESTART,
     tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGRTMIN, &act, 0);
  tst_assert_sys_sigaction (ERI_SIGRTMIN + 1, &act, 0);

  raise_args[0].args.top = tst_stack_top (stack[0]);
  raise_args[0].args.delay = tst_rand (&rand, 256, 512);
  raise_args[0].sig = ERI_SIGRTMIN;
  raise_args[0].count = 1;
  raise_args[1].args.top = tst_stack_top (stack[1]);
  raise_args[1].args.delay = tst_rand (&rand, 256, 512);
  raise_args[1].sig = ERI_SIGRTMIN + 1;
  raise_args[1].count = 1;
  wake_args.top = tst_stack_top (stack[2]);
  wake_args.delay = tst_rand (&rand, 256, 1024);
  wake_args.fn = wake;

#if 0
  tst_assert_syscall (pipe2, pipe, ERI_O_DIRECT);
#endif

  tst_assert_live_clone_raise (raise_args);
  tst_assert_live_clone_raise (raise_args + 1);
  tst_assert_live_clone (&wake_args);

  uint8_t pre = tst_atomic_load (&hand, 1);
  uint64_t res = tst_syscall (futex, &futex, ERI_FUTEX_WAIT_PRIVATE, 0, 0);
  eri_assert (eri_syscall_is_ok (res) || res  == ERI_EAGAIN);
#if 0
  char buf;
  tst_assert_syscall (read, pipe[0], &buf, 1);
  eri_assert (buf == 0xab);
#endif
  uint8_t post = tst_atomic_load (&hand, 1);


  tst_assert_sys_futex_wait (&raise_args[0].args.alive, 1, 0);
  tst_assert_sys_futex_wait (&raise_args[1].args.alive, 1, 0);
  tst_assert_sys_futex_wait (&wake_args.alive, 1, 0);

  eri_info ("pre = %u, post = %u\n", pre, post);
#if 0
  tst_assert_syscall (close, pipe[0]);
  tst_assert_syscall (close, pipe[1]);
#endif

  tst_assert_sys_exit (0);
}
