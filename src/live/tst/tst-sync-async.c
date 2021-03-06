#include <public/public.h>
#define ERI_APPLY_ERS

#include <public/public.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static uint8_t stack[1024 * 1024];
static struct tst_live_clone_raise_args raise_args;

#define sync_async_loop(c) \
  do {									\
    register uint64_t _c asm ("rcx") = c;				\
    asm (ERI_STR (ERS_SYNC_ASYNC (1, 1: loop	1b)) : : "r" (_c));	\
  } while (0)

static uint8_t pass;

static void
sig_trap (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_assert (! pass);

  static uint8_t i;
  if (! i)
    {
      eri_info ("single step: %lx\n", ctx->mctx.rip);
      i = 1;
    }
  else eri_debug ("single step: %lx\n", ctx->mctx.rip);

  eri_assert (sig == ERI_SIGTRAP);
  eri_assert (eri_si_single_step (info));
}

static eri_noreturn void
sig_int (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_debug ("sig int: %lx\n", ctx->mctx.rip);
  eri_assert (sig == ERI_SIGINT && info->code == ERI_SI_TKILL);

  tst_assert_sys_futex_wait (&raise_args.args.alive, 1, 0);

  if (pass++ == 0)
    {
      raise_args.args.delay = 0;
      tst_assert_live_clone_raise (&raise_args);

      while (1) sync_async_loop (1024);
    }
  else tst_assert_sys_exit (0);
}

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  struct eri_sigaction act = {
    sig_trap, ERI_SA_SIGINFO | ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGTRAP, &act, 0);

  act.act = sig_int;
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  raise_args.args.top = tst_stack_top (stack);
  raise_args.args.delay = tst_rand (&rand, 0, 64);
  raise_args.count = 1;

  tst_assert_live_clone_raise (&raise_args);
  tst_enable_trace ();
  sync_async_loop (-1);
  eri_assert_unreachable ();
}
