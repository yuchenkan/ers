#ifndef ERI_LIVE_H
#define ERI_LIVE_H

#define ERI_LIVE_ATOMIC_LABEL(sz, label) \
  _ERS_PASTE (atomic_, _ERS_PASTE (label, sz))

#define ERI_TST_LIVE_COMPLETE_START_NAME(name) \
  _ERS_PASTE (eri_tst_live_, _ERS_PASTE (name, _complete_start))

#define ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME(sz, name) \
  ERI_TST_LIVE_COMPLETE_START_NAME (ERI_LIVE_ATOMIC_LABEL (sz, name))

#ifndef __ASSEMBLER__

#include "recorder.h"
#include "lib/syscall.h"

struct eri_live_internal
{
  uint64_t *atomic_mem_table;
};

struct eri_live_thread
{
  struct eri_common_thread common;

  uint64_t entry;

  uint64_t top;
  uint64_t top_saved;
  uint64_t rsp;
  uint64_t stack_size;
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

  uint64_t fix_restart;
  uint64_t fix_restart_rax;
  uint64_t fix_restart_rbx;
  uint64_t fix_restart_rip;
  uint64_t fix_restart_rflags;

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

extern uint8_t eri_live_thread_text[];
extern uint8_t eri_live_thread_text_resume[];
extern uint8_t eri_live_thread_text_entry[];
extern uint8_t eri_live_thread_text_resume_ret[];
extern uint8_t eri_live_thread_text_internal_cont[];
extern uint8_t eri_live_thread_text_external_cont[];
extern uint8_t eri_live_thread_text_cont_end[];
extern uint8_t eri_live_thread_text_ret[];
extern uint8_t eri_live_thread_text_ret_end[];
extern uint8_t eri_live_thread_text_end[];

void eri_live_sigaction (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *uctx);

extern uint8_t eri_live_resume_ret[];

void eri_live_entry (void);

extern uint8_t ERI_TST_LIVE_COMPLETE_START_NAME (syscall)[];

#define ERI_TST_EXTERN_ATOMIC_COMPLETE_STARTS(name) \
extern uint8_t ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (b, name)[]; \
extern uint8_t ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (w, name)[]; \
extern uint8_t ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (l, name)[]; \
extern uint8_t ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, name)[];

ERI_TST_EXTERN_ATOMIC_COMPLETE_STARTS (load)
ERI_TST_EXTERN_ATOMIC_COMPLETE_STARTS (stor)
ERI_TST_EXTERN_ATOMIC_COMPLETE_STARTS (inc)
ERI_TST_EXTERN_ATOMIC_COMPLETE_STARTS (dec)
ERI_TST_EXTERN_ATOMIC_COMPLETE_STARTS (xchg)
ERI_TST_EXTERN_ATOMIC_COMPLETE_STARTS (cmpxchg)

void eri_live_init_thread (struct eri_live_thread *th, void *internal,
			   uint64_t stack_top, uint64_t stack_size);

#endif

#define ERI_LIVE_INTERNAL_ATOMIC_MEM_TABLE	0 // TODO

#define ERI_LIVE_ENTRY_SAVED_REG_SIZE	80

#endif
