#include "lib/offset.h"
#include "live.h"
#include "lib/util.h"

#define LIVE_THREAD_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_THREAD_, name, struct eri_live_thread, member)

void
declare (void)
{
  LIVE_THREAD_OFFSET (ENTRY, entry);

  LIVE_THREAD_OFFSET (TOP, top);
  LIVE_THREAD_OFFSET (TOP_SAVED, top_saved);
  LIVE_THREAD_OFFSET (RSP, rsp);
  LIVE_THREAD_OFFSET (RFLAGS_SAVED, rflags_saved);
  LIVE_THREAD_OFFSET (TRACE_FLAG, trace_flag);

  LIVE_THREAD_OFFSET (THREAD_INTERNAL_CONT, thread_internal_cont);
  LIVE_THREAD_OFFSET (THREAD_EXTERNAL_CONT, thread_external_cont);
  LIVE_THREAD_OFFSET (THREAD_CONT_END, thread_cont_end);

  LIVE_THREAD_OFFSET (THREAD_RET, thread_ret);
  LIVE_THREAD_OFFSET (THREAD_RET_END, thread_ret_end);

  LIVE_THREAD_OFFSET (THREAD_RESUME, thread_resume);
  LIVE_THREAD_OFFSET (RESUME, resume);
  LIVE_THREAD_OFFSET (THREAD_RESUME_RET, thread_resume_ret);
  LIVE_THREAD_OFFSET (RESUME_RET, resume_ret);

  LIVE_THREAD_OFFSET (COMPLETE_START, complete_start);

  LIVE_THREAD_OFFSET (FIX_RESTART, fix_restart);
  LIVE_THREAD_OFFSET (FIX_RESTART_RAX, fix_restart_rax);
  LIVE_THREAD_OFFSET (FIX_RESTART_RBX, fix_restart_rbx);
  LIVE_THREAD_OFFSET (FIX_RESTART_RIP, fix_restart_rip);
  LIVE_THREAD_OFFSET (FIX_RESTART_RFLAGS, fix_restart_rflags);
  LIVE_THREAD_OFFSET (RESTART, restart);
  LIVE_THREAD_OFFSET (RESTART_START, restart_start);

  LIVE_THREAD_OFFSET (SIG_RBX, sig_rbx);
  LIVE_THREAD_OFFSET (SIG_RDI, sig_rdi);
  LIVE_THREAD_OFFSET (SIG_RSI, sig_rsi);
  LIVE_THREAD_OFFSET (SIG_RDX, sig_rdx);
  LIVE_THREAD_OFFSET (SIG_RSP, sig_rsp);
  LIVE_THREAD_OFFSET (SIG_RBP, sig_rbp);
  LIVE_THREAD_OFFSET (SIG_R12, sig_r12);
  LIVE_THREAD_OFFSET (SIG_R13, sig_r13);
  LIVE_THREAD_OFFSET (SIG_R14, sig_r14);
  LIVE_THREAD_OFFSET (SIG_R15, sig_r15);

  LIVE_THREAD_OFFSET (TST_SKIP_CTF, tst_skip_ctf);

  ERI_DECLARE_SYMBOL (ERI_LIVE_THREAD_SIZE16,
		      eri_round_up (sizeof (struct eri_live_thread), 16));
}
