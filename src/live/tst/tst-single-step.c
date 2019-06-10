#define ERI_APPLY_ERS

#include <public/public.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static int32_t tid;
static uint64_t steps;
static uint64_t raise_steps;
static uint64_t clone_steps;
static char *src = "abcdef";

static uint8_t stack[1024 * 1024];

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_debug ("single step: %lx\n", ctx->mctx.rip);

  eri_assert (sig == ERI_SIGTRAP);
  if (! eri_si_sync (info))
    {
      tst_atomic_inc (&raise_steps, 0);
      return;
    }

  if (tst_assert_syscall (gettid) != tid)
    tst_atomic_inc (&clone_steps, 0);

  tst_atomic_inc (&steps, 0);
  eri_assert (eri_si_single_step (info));
}

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

  tst_enable_trace ();

  tst_assert_syscall (sched_yield);
  eri_assert (tst_atomic_load (&steps, 0));

  struct tst_live_clone_raise_args args1 = {
    .args.top = tst_stack_top (stack), .sig = ERI_SIGTRAP, .count = 1
  };

  tst_assert_live_clone_raise (&args1);

  char dst[eri_strlen (src)];
  register char *d asm ("rdi") = dst;
  register char *s asm ("rsi") = src;
  register uint32_t c asm ("ecx") = sizeof dst;
  asm (ERI_STR (ERS_SYNC_ASYNC (1, rep movsb))
       : : "r" (c), "r" (d), "r" (s) : "memory");

  tst_assert_sys_futex_wait (&args1.args.alive, 1, 0);
  eri_assert (tst_atomic_load (&raise_steps, 0));

  struct tst_live_clone_args args2 = {
    .top = tst_stack_top (stack), .delay = 1
  };
  tst_assert_live_clone (&args2);
  tst_assert_sys_futex_wait (&args2.alive, 1, 0);
  eri_assert (tst_atomic_load (&clone_steps, 0));

  tst_assert_sys_exit (0);
}
