#ifndef ERI_LIVE_ENTRY_H
#define ERI_LIVE_ENTRY_H

#include "public/common.h"

#define _ERI_R0_b(i)		_ERS_PASTE (i, l)
#define _ERI_R0_w(i)		_ERS_PASTE (i, x)
#define _ERI_R0_l(i)		_ERS_PASTE2 (e, i, x)
#define _ERI_R0_q(i)		_ERS_PASTE2 (r, i, x)

#define ERI_RAX(sz)		_ERS_PASTE (_ERI_R0_, sz) (a)
#define ERI_RBX(sz)		_ERS_PASTE (_ERI_R0_, sz) (b)
#define ERI_RDX(sz)		_ERS_PASTE (_ERI_R0_, sz) (d)
#define ERI_RCX(sz)		_ERS_PASTE (_ERI_R0_, sz) (c)

#define _ERI_R1_b(i)		_ERS_PASTE (i, l)
#define _ERI_R1_w(i)		i
#define _ERI_R1_l(i)		_ERS_PASTE (e, i)
#define _ERI_R1_q(i)		_ERS_PASTE (r, i)

#define ERI_RDI(sz)		_ERS_PASTE (_ERI_R1_, sz) (di)
#define ERI_RSI(sz)		_ERS_PASTE (_ERI_R1_, sz) (si)
#define ERI_RSP(sz)		_ERS_PASTE (_ERI_R1_, sz) (sp)
#define ERI_RBP(sz)		_ERS_PASTE (_ERI_R1_, sz) (bp)

#define _ERI_R2_b(i)		_ERS_PASTE (i, b)
#define _ERI_R2_w(i)		_ERS_PASTE (i, w)
#define _ERI_R2_l(i)		_ERS_PASTE (i, d)
#define _ERI_R2_q(i)		i

#define ERI_R8(sz)		_ERS_PASTE (_ERI_R2_, sz) (r8)
#define ERI_R9(sz)		_ERS_PASTE (_ERI_R2_, sz) (r9)
#define ERI_R10(sz)		_ERS_PASTE (_ERI_R2_, sz) (r10)
#define ERI_R11(sz)		_ERS_PASTE (_ERI_R2_, sz) (r11)
#define ERI_R12(sz)		_ERS_PASTE (_ERI_R2_, sz) (r12)
#define ERI_R13(sz)		_ERS_PASTE (_ERI_R2_, sz) (r13)
#define ERI_R14(sz)		_ERS_PASTE (_ERI_R2_, sz) (r14)
#define ERI_R15(sz)		_ERS_PASTE (_ERI_R2_, sz) (r15)

#define ERI_LIVE_ENTRY_SAVED_REG_SIZE		80
#define ERI_LIVE_SIG_STACK_SIZE			4096

#define ERI_LIVE_ATOMIC_LABEL(sz, label) \
  _ERS_PASTE2 (atomic_, label, sz)

#define ERI_TST_LIVE_COMPLETE_START_NAME(name) \
  _ERS_PASTE2 (eri_tst_live_, name, _complete_start)

#define ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME(sz, name) \
  ERI_TST_LIVE_COMPLETE_START_NAME (ERI_LIVE_ATOMIC_LABEL (sz, name))


#ifndef __ASSEMBLER__

#include "entry.h"
#include "rtld.h"
#include "lib/syscall.h"

struct eri_live_thread_entry
{
  struct eri_public_thread_entry public;

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

  uint64_t syscall_rsp;
  uint64_t sync_repeat_trace;

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

  void *thread;

  uint64_t tst_skip_ctf;
};

extern uint64_t *eri_live_entry_atomic_mem_table;

extern uint8_t eri_live_thread_entry_text[];
extern uint8_t eri_live_thread_entry_text_resume[];
extern uint8_t eri_live_thread_entry_text_entry[];
extern uint8_t eri_live_thread_entry_text_resume_ret[];
extern uint8_t eri_live_thread_entry_text_internal_cont[];
extern uint8_t eri_live_thread_entry_text_external_cont[];
extern uint8_t eri_live_thread_entry_text_cont_end[];
extern uint8_t eri_live_thread_entry_text_ret[];
extern uint8_t eri_live_thread_entry_text_ret_end[];
extern uint8_t eri_live_thread_entry_text_end[];

void eri_live_entry_start (struct eri_live_thread_entry *entry,
			   struct eri_rtld *rtld) __attribute__ ((noreturn));

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

void eri_live_init_thread_entry (struct eri_live_thread_entry *entry,
		void *thread, uint64_t stack_top, uint64_t stack_size,
		void *sig_stack);

struct eri_live_entry_syscall_info
{
  uint64_t rax;
  uint64_t rsp; /* XXX */
  uint64_t r11;
  uint64_t rflags;
};

struct eri_live_entry_sigaction_info
{
  uint64_t rsi;
  uint64_t rdx;
  uint64_t rsp;
  uint64_t rip;
  uint64_t mask_all;
  struct eri_sigset mask;
};

#endif

#endif
