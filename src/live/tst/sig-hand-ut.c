#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/atomic.h>

#include <live/signal-thread.h>

#include <live/tst/tst-util.h>
#include <live/tst/sig-hand-ut.h>

TST_UNUSED (eri_helper__invoke)

void
eri_live_signal_thread__init_thread_sig_stack (
		struct eri_live_signal_thread *sig_th,
		uint8_t *stack, uint64_t stack_size)
{
  struct eri_stack st = {
    (uint64_t) stack, ERI_SS_AUTODISARM, stack_size
  };
  eri_assert_syscall (sigaltstack, &st, 0);
  *(struct eri_live_signal_thread **) stack = sig_th;
  eri_atomic_store (&sig_th->sig_alt_stack_installed, 1, 0);

  if (sig_th->init_sig_stack_enable_trace)
    tst_enable_trace ();
}

uint8_t
eri_live_signal_thread__sig_mask_all (
		struct eri_live_signal_thread *sig_th)
{
  return 1;
}

void
eri_live_signal_thread__sig_reset (
		struct eri_live_signal_thread *sig_th,
		const struct eri_sigset *mask)
{
  eri_atomic_store (&sig_th->sig_reset, 1, 0);
}

const struct eri_sigset *
eri_live_signal_thread__get_sig_mask (
		const struct eri_live_signal_thread *sig_th)
{
  return &sig_th->mask;
}

#define ZERO(func) \
TST_WEAK_BLANK_ZERO (ERI_PASTE (eri_live_signal_thread__, func))

ZERO (get_id)
ZERO (get_log)
ZERO (signaled)

#define UNUSED(func) \
TST_UNUSED (ERI_PASTE (eri_live_signal_thread__, func))

UNUSED (clone)
UNUSED (die)
UNUSED (exit)
UNUSED (sig_action)
UNUSED (sig_fd_read)
UNUSED (sig_mask_async)
UNUSED (sig_prepare)
UNUSED (sig_tmp_mask_async)
UNUSED (syscall)
UNUSED (set_futex_pi_owner)
