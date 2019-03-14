#include <common.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/atomic.h>
#include <lib/syscall.h>

#include <live/signal-thread-local.h>
#include <live/tst/tst-util.h>

TST_UNUSED (sig_handler_frame);
TST_UNUSED (init_group);
TST_UNUSED (start_group);

TST_UNUSED (eri_assert_lock);
TST_UNUSED (eri_assert_unlock);
TST_UNUSED (eri_buf_reserve);

static struct eri_siginfo info = { ERI_SIGINT };
static struct eri_live_signal_thread sig_th;  
static struct eri_ucontext *sig_ctx;

static void
sig_int (int32_t sig)
{
  sig_th.sig_info = &info;

  if (sig_th.event_sig_restart
      && sig_ctx->mctx.rip != sig_th.event_sig_reset_restart)
    sig_ctx->mctx.rip = sig_th.event_sig_restart;
}

static int32_t pid;
static int32_t tid;

static uint32_t step_count;
static uint32_t raise_at;
static uint8_t done;
static uint8_t reach_done;

static void
step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (done)
    {
      reach_done = 1;
      ctx->mctx.rflags &= ~ERI_RFLAGS_TRACE_MASK;
      return;
    }

  if (step_count++ == raise_at)
    {
      sig_ctx = ctx;
      eri_assert_syscall (tgkill, pid, tid, ERI_SIGINT);
      ctx->mctx.rflags &= ~ERI_RFLAGS_TRACE_MASK;
    }
}

static void
signal (void)
{
  step_count = 0;
  done = 0;
  sig_th.sig_info = 0;

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_sig_add_set (&mask, ERI_SIGINT);

  tst_enable_trace ();
  uint32_t res = sig_mask_async (&sig_th, &mask);
  eri_atomic_store (&done, 1);

  eri_assert_sys_sigprocmask (0, &mask);

  if (res)
    {
      eri_assert (eri_sig_set_set (&mask, ERI_SIGINT));
      eri_assert (! sig_th.sig_info);
      eri_sig_empty_set (&mask);
      eri_assert_sys_sigprocmask (&mask, 0);
    }
  else
    {
      eri_assert (! eri_sig_set_set (&mask, ERI_SIGINT));
      eri_assert (sig_th.sig_info);
    }
}

eri_noreturn void tst_main (void);

eri_noreturn void
tst_main (void)
{
  sig_th.sig_info = 0;
  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_sig_add_set (&mask, ERI_SIGINT);
  eri_assert (sig_mask_async (&sig_th, &mask));
  sig_th.sig_info = &info;
  eri_assert (! sig_mask_async (&sig_th, &mask));

  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  pid = eri_assert_syscall (getpid);
  tid = eri_assert_syscall (gettid);

  struct eri_sigaction trap_act = {
    step, ERI_SA_SIGINFO | ERI_SA_RESTORER, eri_assert_sys_sigreturn
  };
  eri_assert_sys_sigaction (ERI_SIGTRAP, &trap_act, 0);

  struct eri_sigaction int_act = {
    sig_int, ERI_SA_RESTORER, eri_assert_sys_sigreturn
  };
  eri_assert_sys_sigaction (ERI_SIGINT, &int_act, 0);

  for (; ! reach_done; ++raise_at) signal ();

  eri_assert_printf ("final raise_at = %u\n", raise_at);
  eri_assert_sys_exit (0);
}
