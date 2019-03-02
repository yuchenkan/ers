#include <helper.h>

#include <lib/util.h>
#include <tst/tst-util.h>

void
eri_helper__invoke (struct eri_helper *helper, void (*fn) (void *),
		    void *args, eri_helper__sigsegv_handler_t segv_hand)
{
  fn (args);
}

#define UNUSED(func) \
TST_UNUSED (ERI_PASTE (eri_live_signal_thread__, func))

UNUSED(clone)
UNUSED(die)
UNUSED(exit)
UNUSED(get_args)
UNUSED(get_pid)
UNUSED(get_pool)
UNUSED(get_sig_mask)
UNUSED(get_tid)
UNUSED(init_thread_sig_stack)
UNUSED(sig_action)
UNUSED(sig_fd_read)
UNUSED(sig_mask_all)
UNUSED(sig_mask_async)
UNUSED(sig_prepare_sync)
UNUSED(sig_reset)
UNUSED(sig_tmp_mask_async)
UNUSED(signaled)
UNUSED(syscall)
