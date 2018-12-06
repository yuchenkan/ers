#ifndef ERI_LIVE_H
#define ERI_LIVE_H

#include "recorder.h"
#include "lib/syscall.h"

struct eri_live_thread
{
  struct eri_common_thread common;

  uint64_t entry;

  uint64_t top;
  uint64_t top16;
  uint64_t rsp;
  uint64_t rflags_saved;
  uint64_t trace_flag;

  uint64_t thread_internal_cont;
  uint64_t thread_external_cont;
  uint64_t thread_cont_end;

  uint64_t thread_ret;
  uint64_t thread_ret_end;

  uint64_t thread_resume;
  uint64_t resume;
  uint64_t thread_resume_ret;
  uint64_t resume_ret;

  uint64_t complete_start;

  uint64_t restart;
  uint64_t restart_start;

  uint64_t sig_rbx;
  uint64_t sig_rdi;
  uint64_t sig_rsi;
  uint64_t sig_rdx;

  uint64_t sig_rsp;

  uint64_t sig_rbp;
  uint64_t sig_r12;
  uint64_t sig_r13;
  uint64_t sig_r14;
  uint64_t sig_r15;

  uint64_t tst_skip_ctf;
};

extern struct eri_live_thread eri_live_thread_template;

extern uint8_t eri_live_thread_template_text[]; 
extern uint8_t eri_live_thread_template_resume[]; 
extern uint8_t eri_live_thread_template_entry[]; 
extern uint8_t eri_live_thread_template_resume_ret[]; 
extern uint8_t eri_live_thread_template_internal_cont[]; 
extern uint8_t eri_live_thread_template_external_cont[]; 
extern uint8_t eri_live_thread_template_cont_end[]; 
extern uint8_t eri_live_thread_template_ret[]; 
extern uint8_t eri_live_thread_template_ret_end[]; 

void eri_live_sigaction (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *uctx);

extern uint8_t eri_live_resume_ret[];

void eri_live_entry (void);

extern uint8_t eri_tst_live_thread_xchg_complete_start[];
extern uint8_t eri_tst_live_thread_syscall_complete_start[];

#endif
