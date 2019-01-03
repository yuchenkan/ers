#include <stdint.h>

#include "tst/tst-live-entry-common.h"

#include "live.h"
#include "live-entry.h"

#include "lib/atomic.h"
#include "lib/printf.h"

static uint8_t triggered;

void
eri_live_get_sig_action (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx, int32_t intr,
			 struct eri_live_entry_sig_action_info *act_info,
			 void *thread)
{
  eri_assert (act_info->type == ERI_LIVE_ENTRY_SIG_ACTION_UNKNOWN);
  eri_assert (intr == -1);

  eri_assert_printf ("triggered\n");
  eri_atomic_store (&triggered, 1);
  act_info->type = ERI_LIVE_ENTRY_SIG_NO_ACTION;
}

uint64_t
tst_main (void)
{
  uint8_t entry_buf[ERI_LIVE_THREAD_ENTRY_SIZE];
  uint8_t stack[2 * 1024 * 1024];
  uint8_t sig_stack[ERI_LIVE_SIG_STACK_SIZE];
  tst_init_start_live_thread_entry (0, entry_buf,
				    stack, sizeof stack, sig_stack);

  struct eri_sigaction act = {
    eri_live_entry_sig_action,
    ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK, 0
  };
  eri_sigfillset (&act.mask);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGINT, &act, 0, ERI_SIG_SETSIZE);

  ERI_ASSERT_SYSCALL (kill, ERI_ASSERT_SYSCALL_RES (getpid), ERI_SIGINT);

  while (! eri_atomic_load (&triggered)) continue;
  return 0;
}
