#include <public/public.h>

#include <lib/compiler.h>
#include <common/common.h>

#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static int32_t tid;
static uint64_t steps;
static uint64_t raise_steps;
static char *src = "ab";

static uint8_t stack[1024 * 1024];

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_debug ("single step: %lx\n", ctx->mctx.rip);

  if (tst_assert_syscall (gettid) != tid)
    tst_atomic_inc (&raise_steps);

  tst_atomic_inc (&steps);
  eri_assert (sig == ERI_SIGTRAP);
  eri_assert (eri_si_single_step (info));
}

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  tid = tst_assert_syscall (gettid);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGTRAP, &act, 0);

  struct tst_sys_clone_raise_args args;
  tst_sys_clone_raise_init_args (&args, 0, stack, 0, 1);

  tst_enable_trace ();

  tst_assert_syscall (sched_yield);
  eri_assert (tst_atomic_load (&steps));

  char dst[2];
  register char *d asm ("rdi") = dst;
  register char *s asm ("rsi") = src;
  register uint32_t c asm ("ecx") = 2;
  asm (ERI_STR (ERS_SYNC_ASYNC (1, rep movsb))
       : : "r" (c), "r" (d), "r" (s) : "memory");

  tst_assert_sys_clone_raise (&args);
  tst_assert_sys_futex_wait (&args.alive, 1, 0);

  eri_assert (tst_atomic_load (&raise_steps));

  tst_assert_sys_exit (0);
}
