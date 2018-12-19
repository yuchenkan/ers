#include "lib/offset.h"
#include "live-entry.h"
#include "lib/util.h"

#define THREAD_ENTRY_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_THREAD_ENTRY_, name,			\
		      struct eri_live_thread_entry, member)

#define SIGACTION_INFO_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_ENTRY_SIGACTION_INFO_, name,		\
		      struct eri_live_entry_sigaction_info, member)

#define SYSCALL_INFO_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_ENTRY_SYSCALL_INFO_, name,		\
		      struct eri_live_entry_syscall_info, member)

#define CLONE_INFO_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_ENTRY_CLONE_INFO_, name,			\
		      struct eri_live_entry_clone_info, member)

void
declare (void)
{
  THREAD_ENTRY_OFFSET (ENTRY, entry);

  THREAD_ENTRY_OFFSET (TOP, top);
  THREAD_ENTRY_OFFSET (TOP_SAVED, top_saved);
  THREAD_ENTRY_OFFSET (RSP, rsp);
  THREAD_ENTRY_OFFSET (STACK_SIZE, stack_size);
  THREAD_ENTRY_OFFSET (RFLAGS_SAVED, rflags_saved);
  THREAD_ENTRY_OFFSET (TRACE_FLAG, trace_flag);

  THREAD_ENTRY_OFFSET (THREAD_INTERNAL_CONT, thread_internal_cont);
  THREAD_ENTRY_OFFSET (THREAD_EXTERNAL_CONT, thread_external_cont);
  THREAD_ENTRY_OFFSET (THREAD_CONT_END, thread_cont_end);

  THREAD_ENTRY_OFFSET (THREAD_RET, thread_ret);
  THREAD_ENTRY_OFFSET (THREAD_RET_END, thread_ret_end);

  THREAD_ENTRY_OFFSET (THREAD_RESUME, thread_resume);
  THREAD_ENTRY_OFFSET (RESUME, resume);
  THREAD_ENTRY_OFFSET (THREAD_RESUME_RET, thread_resume_ret);
  THREAD_ENTRY_OFFSET (RESUME_RET, resume_ret);

  THREAD_ENTRY_OFFSET (COMPLETE_START, complete_start);

  THREAD_ENTRY_OFFSET (FIX_RESTART, fix_restart);
  THREAD_ENTRY_OFFSET (FIX_RESTART_RAX, fix_restart_rax);
  THREAD_ENTRY_OFFSET (FIX_RESTART_RBX, fix_restart_rbx);
  THREAD_ENTRY_OFFSET (FIX_RESTART_RIP, fix_restart_rip);
  THREAD_ENTRY_OFFSET (FIX_RESTART_RFLAGS, fix_restart_rflags);

  THREAD_ENTRY_OFFSET (RESTART, restart);
  THREAD_ENTRY_OFFSET (RESTART_START, restart_start);

  THREAD_ENTRY_OFFSET (EXT_RBP, ext_rbp);
  THREAD_ENTRY_OFFSET (EXT_R12, ext_r12);
  THREAD_ENTRY_OFFSET (EXT_R13, ext_r13);
  THREAD_ENTRY_OFFSET (EXT_R14, ext_r14);
  THREAD_ENTRY_OFFSET (EXT_R15, ext_r15);

  THREAD_ENTRY_OFFSET (SYSCALL_RSP, syscall_rsp);
  THREAD_ENTRY_OFFSET (SYSCALL_NEW_THREAD, syscall_new_thread);
  THREAD_ENTRY_OFFSET (SYNC_REPEAT_TRACE, sync_repeat_trace);

  THREAD_ENTRY_OFFSET (SIG_RBX, sig_rbx);
  THREAD_ENTRY_OFFSET (SIG_RDI, sig_rdi);
  THREAD_ENTRY_OFFSET (SIG_RSI, sig_rsi);
  THREAD_ENTRY_OFFSET (SIG_RDX, sig_rdx);
  THREAD_ENTRY_OFFSET (SIG_RSP, sig_rsp);
  THREAD_ENTRY_OFFSET (SIG_RBP, sig_rbp);
  THREAD_ENTRY_OFFSET (SIG_R12, sig_r12);
  THREAD_ENTRY_OFFSET (SIG_R13, sig_r13);
  THREAD_ENTRY_OFFSET (SIG_R14, sig_r14);
  THREAD_ENTRY_OFFSET (SIG_R15, sig_r15);

  THREAD_ENTRY_OFFSET (SIG_STACK, sig_stack);

  THREAD_ENTRY_OFFSET (THREAD, thread);

#ifndef ERI_NON_TST
  THREAD_ENTRY_OFFSET (TST_SKIP_CTF, tst_skip_ctf);
#endif

  ERI_DECLARE_SYMBOL (ERI_LIVE_THREAD_ENTRY_SIZE16,
		      eri_size_of (struct eri_live_thread_entry, 16));

  SYSCALL_INFO_OFFSET (RAX, rax);
  SYSCALL_INFO_OFFSET (R11, r11);
  SYSCALL_INFO_OFFSET (RFLAGS, rflags);

  SYSCALL_INFO_OFFSET (TST_CLONE_TF, tst_clone_tf);

  ERI_DECLARE_SYMBOL (ERI_LIVE_ENTRY_SYSCALL_INFO_SIZE16,
		      eri_size_of (struct eri_live_entry_syscall_info, 16));

  SIGACTION_INFO_OFFSET (RSI, rsi);
  SIGACTION_INFO_OFFSET (RDX, rdx);
  SIGACTION_INFO_OFFSET (RSP, rsp);
  SIGACTION_INFO_OFFSET (RIP, rip);
  SIGACTION_INFO_OFFSET (MASK_ALL, mask.mask_all);
  SIGACTION_INFO_OFFSET (MASK, mask.mask);

  ERI_DECLARE_SYMBOL (ERI_LIVE_ENTRY_SIGACTION_INFO_SIZE16,
		      eri_size_of (struct eri_live_entry_sigaction_info, 16));

  CLONE_INFO_OFFSET (FLAGS, flags);
  CLONE_INFO_OFFSET (CHILD_STACK, child_stack);
  CLONE_INFO_OFFSET (PTID, ptid);
  CLONE_INFO_OFFSET (CTID, ctid);
  CLONE_INFO_OFFSET (NEWTLS, newtls);
}
