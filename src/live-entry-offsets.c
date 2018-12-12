#include "lib/offset.h"
#include "live-entry.h"
#include "lib/util.h"

#define THREAD_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_THREAD_, name, struct eri_live_thread, member)

#define SYSCALL_INFO_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_SYSCALL_INFO_, name,			\
		      struct eri_live_syscall_info, member)

void
declare (void)
{
  THREAD_OFFSET (ENTRY, entry);

  THREAD_OFFSET (TOP, top);
  THREAD_OFFSET (TOP_SAVED, top_saved);
  THREAD_OFFSET (RSP, rsp);
  THREAD_OFFSET (STACK_SIZE, stack_size);
  THREAD_OFFSET (RFLAGS_SAVED, rflags_saved);
  THREAD_OFFSET (TRACE_FLAG, trace_flag);

  THREAD_OFFSET (THREAD_INTERNAL_CONT, thread_internal_cont);
  THREAD_OFFSET (THREAD_EXTERNAL_CONT, thread_external_cont);
  THREAD_OFFSET (THREAD_CONT_END, thread_cont_end);

  THREAD_OFFSET (THREAD_RET, thread_ret);
  THREAD_OFFSET (THREAD_RET_END, thread_ret_end);

  THREAD_OFFSET (THREAD_RESUME, thread_resume);
  THREAD_OFFSET (RESUME, resume);
  THREAD_OFFSET (THREAD_RESUME_RET, thread_resume_ret);
  THREAD_OFFSET (RESUME_RET, resume_ret);

  THREAD_OFFSET (COMPLETE_START, complete_start);

  THREAD_OFFSET (FIX_RESTART, fix_restart);
  THREAD_OFFSET (FIX_RESTART_RAX, fix_restart_rax);
  THREAD_OFFSET (FIX_RESTART_RBX, fix_restart_rbx);
  THREAD_OFFSET (FIX_RESTART_RIP, fix_restart_rip);
  THREAD_OFFSET (FIX_RESTART_RFLAGS, fix_restart_rflags);

  THREAD_OFFSET (RESTART, restart);
  THREAD_OFFSET (RESTART_START, restart_start);

  THREAD_OFFSET (SYSCALL_RSP, syscall_rsp);
  THREAD_OFFSET (SYNC_REPEAT_TRACE, sync_repeat_trace);

  THREAD_OFFSET (SIG_RBX, sig_rbx);
  THREAD_OFFSET (SIG_RDI, sig_rdi);
  THREAD_OFFSET (SIG_RSI, sig_rsi);
  THREAD_OFFSET (SIG_RDX, sig_rdx);
  THREAD_OFFSET (SIG_RSP, sig_rsp);
  THREAD_OFFSET (SIG_RBP, sig_rbp);
  THREAD_OFFSET (SIG_R12, sig_r12);
  THREAD_OFFSET (SIG_R13, sig_r13);
  THREAD_OFFSET (SIG_R14, sig_r14);
  THREAD_OFFSET (SIG_R15, sig_r15);

  THREAD_OFFSET (TST_SKIP_CTF, tst_skip_ctf);

  ERI_DECLARE_SYMBOL (ERI_LIVE_THREAD_SIZE16,
		      eri_size_of (struct eri_live_thread, 16));

  SYSCALL_INFO_OFFSET (RAX, rax);
  SYSCALL_INFO_OFFSET (R11, r11);
  SYSCALL_INFO_OFFSET (RFLAGS, rflags);

  ERI_DECLARE_SYMBOL (ERI_LIVE_SYSCALL_INFO_SIZE16,
		      eri_size_of (struct eri_live_syscall_info, 16));
}
