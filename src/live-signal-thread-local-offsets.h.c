#include <live-signal-thread-local.h>

#include <lib/offset.h>

#define SIGNAL_THREAD_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (SIGNAL_THREAD_, name, struct eri_live_signal_thread, member)

void
declare (void)
{
  SIGNAL_THREAD_OFFSET (STACK, stack);
  SIGNAL_THREAD_OFFSET (EVENT_SIG_RESTART, event_sig_restart);
  SIGNAL_THREAD_OFFSET (EVENT_SIG_RESET_RESTART, event_sig_reset_restart);
  SIGNAL_THREAD_OFFSET (SIG_INFO, sig_info);
}
