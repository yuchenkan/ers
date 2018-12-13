/* vim: set ft=gas: */

#include "public/impl.h"

#include "lib/syscall.h"
#include "tst/tst-live-entry.h"
#include "tst/tst-live-entry-offsets.h"

  .text

  .align 16
  .global tst_start
  .type tst_start, @function
tst_start:
  call	tst_main
  movq	%rax, %rdi
  movl	$__NR_exit, %eax
  syscall
  .size tst_start, . - tst_start

  .align 16
  .global tst_live_entry
  .hidden tst_live_entry
  .type tst_live_entry, @function
tst_live_entry:
  pushq	%rbx
  pushq	%rbp
  pushq	%r12
  pushq	%r13
  pushq	%r14
  pushq	%r15

  movq	%rsp, %rax
  movq	TST_CONTEXT_RSP(%rdi), %rsp
  pushq	%rax

  leaq	.ltst_live_entry_ctf(%rip), %rax
  pushq	%rax

  movq	TST_CONTEXT_RAX(%rdi), %rax
  movq	TST_CONTEXT_RBX(%rdi), %rbx
  movq	TST_CONTEXT_RCX(%rdi), %rcx
  movq	TST_CONTEXT_RDX(%rdi), %rdx
  movq	TST_CONTEXT_RSI(%rdi), %rsi
  movq	TST_CONTEXT_RBP(%rdi), %rbp
  movq	TST_CONTEXT_R8(%rdi), %r8
  movq	TST_CONTEXT_R9(%rdi), %r9
  movq	TST_CONTEXT_R10(%rdi), %r10
  movq	TST_CONTEXT_R11(%rdi), %r11
  movq	TST_CONTEXT_R12(%rdi), %r12
  movq	TST_CONTEXT_R13(%rdi), %r13
  movq	TST_CONTEXT_R14(%rdi), %r14
  movq	TST_CONTEXT_R15(%rdi), %r15

  pushq	TST_CONTEXT_RIP(%rdi)
  pushq	TST_CONTEXT_RFLAGS(%rdi)
  movq	TST_CONTEXT_RDI(%rdi), %rdi
  popfq
  ret
.ltst_live_entry_ctf:
  pushfq
  andq	$~ERI_TRACE_FLAG_MASK, (%rsp)
  popfq

  popq	%rsp

  popq	%r15
  popq	%r14
  popq	%r13
  popq	%r12
  popq	%rbp
  popq	%rbx
  ret
  .size tst_live_entry, . - tst_live_entry

#define TST_LIVE_ENTRY(entry, raw, tst, ...) \
  .align 16;								\
  .global _ERS_PASTE (tst_live_entry_raw_enter_, entry);		\
  .hidden _ERS_PASTE (tst_live_entry_raw_enter_, entry);		\
  .global _ERS_PASTE (tst_live_entry_raw_leave_, entry);		\
  .hidden _ERS_PASTE (tst_live_entry_raw_leave_, entry);		\
  .global _ERS_PASTE (tst_live_entry_enter_, entry);			\
  .hidden _ERS_PASTE (tst_live_entry_enter_, entry);			\
  .global _ERS_PASTE (tst_live_entry_leave_, entry);			\
  .hidden _ERS_PASTE (tst_live_entry_leave_, entry);			\
_ERS_PASTE (tst_live_entry_raw_enter_, entry):				\
  raw (__VA_ARGS__);							\
_ERS_PASTE (tst_live_entry_raw_leave_, entry):				\
  ret;									\
_ERS_PASTE (tst_live_entry_enter_, entry):				\
  tst (__VA_ARGS__);							\
_ERS_PASTE (tst_live_entry_leave_, entry):				\
  ret;

#define RAW_SYSCALL()	syscall
#define SYSCALL()	_ERS_SYSCALL

TST_LIVE_ENTRY (syscall, RAW_SYSCALL, SYSCALL)

#define SYNC_JMP_REG		TST_LIVE_SYNC_JMP_REG

#define TST_SYNC_JMP(raw) \
  ERI_PP_IIF (raw,							\
	      jmp	*(%SYNC_JMP_REG),				\
	      _ERS_SYNC_ASYNC (jmp	*(%SYNC_JMP_REG)));		\
  nop;									\

#define RAW_SYNC_JMP()	TST_SYNC_JMP (1)
#define SYNC_JMP()	TST_SYNC_JMP (0)

TST_LIVE_ENTRY (sync_jmp, RAW_SYNC_JMP, SYNC_JMP)

#define RAW_SYNC_REP() \
  .global tst_live_raw_sync_rep;					\
tst_live_raw_sync_rep:							\
  rep movsq;
#define SYNC_REP() \
  _ERS_SYNC_ASYNC (.global tst_live_sync_rep;				\
tst_live_sync_rep:							\
  rep movsq);

TST_LIVE_ENTRY (sync_rep, RAW_SYNC_REP, SYNC_REP)

#define LOAD_REG_DST		TST_LIVE_LOAD_REG_DST
#define LOAD_REG_MEM		TST_LIVE_LOAD_REG_MEM

#define RAW_LOAD(sz) \
  _ERS_PASTE (mov, sz)	(%LOAD_REG_MEM), %LOAD_REG_DST (sz)
#define LOAD(sz) \
  _ERS_ATOMIC_LOAD (sz, (%LOAD_REG_MEM), %LOAD_REG_DST (sz))

#define TST_LOAD(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (load, sz), RAW_LOAD, LOAD, sz)

TST_ATOMIC_SIZES (TST_LOAD)

#define CMP_REG			TST_LIVE_CMP_REG
#define CMP_REG_MEM		TST_LIVE_CMP_REG_MEM

#define RAW_CMP(sz) \
  _ERS_PASTE (cmp, sz)	%CMP_REG (sz), (%CMP_REG_MEM)

#define TST_LOAD_CMP(sz, res, reg) \
  _ERS_PASTE (cmp, sz)	reg, res

#define TST_ATOMIC_CMP(sz, reg, mem) \
  _ERS_ATOMIC_COMMON_LOAD (sz, mem, TST_LOAD_CMP, reg)

#define CMP(sz) \
  TST_ATOMIC_CMP (sz, %CMP_REG (sz), (%CMP_REG_MEM))

#define TST_CMP(sz, name) \
  TST_LIVE_ENTRY (_ERS_PASTE (name, sz), RAW_CMP, CMP, sz)

TST_ATOMIC_SIZES (TST_CMP, cmp_eq)
TST_ATOMIC_SIZES (TST_CMP, cmp_ne)

#define STOR_IMM_VAL		TST_LIVE_STOR_IMM_VAL
#define STOR_REG_SRC		TST_LIVE_STOR_REG_SRC
#define STOR_REG_MEM		TST_LIVE_STOR_REG_MEM

#define RAW_STOR_IMM(sz) \
  _ERS_PASTE (mov, sz)	$STOR_IMM_VAL (sz), (%STOR_REG_MEM)
#define STOR_IMM(sz) \
  _ERS_ATOMIC_STOR (sz, $STOR_IMM_VAL (sz), (%STOR_REG_MEM))

#define TST_STOR_IMM(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (stor_imm, sz), RAW_STOR_IMM, STOR_IMM, sz)

#define RAW_STOR_REG(sz) \
  _ERS_PASTE (mov, sz)	%STOR_REG_SRC (sz), (%STOR_REG_MEM)
#define STOR_REG(sz) \
  _ERS_ATOMIC_STOR (sz, %STOR_REG_SRC (sz), (%STOR_REG_MEM))

#define TST_STOR_REG(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (stor_reg, sz), RAW_STOR_REG, STOR_REG, sz)

TST_ATOMIC_SIZES32 (TST_STOR_IMM)
TST_ATOMIC_SIZES (TST_STOR_REG)

#define INC_REG_MEM		TST_LIVE_INC_REG_MEM
#define DEC_REG_MEM		TST_LIVE_DEC_REG_MEM

#define RAW_INC_DEC(sz, uinc, inc) \
  _ERS_PASTE (inc, sz)	(%_ERS_PASTE (uinc, _REG_MEM))
#define INC_DEC(sz, uinc, inc) \
  _ERS_PASTE (_ERS_ATOMIC_, uinc) (sz, (%_ERS_PASTE (uinc, _REG_MEM)))

#define TST_INC_DEC(sz, uinc, inc) \
  TST_LIVE_ENTRY (_ERS_PASTE (inc, sz), RAW_INC_DEC, INC_DEC, sz, uinc, inc)

TST_ATOMIC_SIZES (TST_INC_DEC, INC, inc)
TST_ATOMIC_SIZES (TST_INC_DEC, DEC, dec)

#define XCHG_REG		TST_LIVE_XCHG_REG
#define XCHG_REG_MEM		TST_LIVE_XCHG_REG_MEM

#define RAW_XCHG(sz) \
  _ERS_PASTE (xchg, sz)	%XCHG_REG (sz), (%XCHG_REG_MEM)
#define XCHG(sz) \
  _ERS_ATOMIC_XCHG (sz, %XCHG_REG (sz), (%XCHG_REG_MEM))

#define TST_XCHG(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (xchg, sz), RAW_XCHG, XCHG, sz)

TST_ATOMIC_SIZES (TST_XCHG)

#define CMPXCHG_REG		TST_LIVE_CMPXCHG_REG

#define RAW_CMPXCHG(sz) \
  _ERS_PASTE (cmpxchg, sz)	%CMPXCHG_REG (sz), (%CMPXCHG_REG (q))
#define CMPXCHG(sz) \
  _ERS_ATOMIC_CMPXCHG (sz, %CMPXCHG_REG (sz), (%CMPXCHG_REG (q)))

#define TST_CMPXCHG(sz, name) \
  TST_LIVE_ENTRY (_ERS_PASTE (name, sz), RAW_CMPXCHG, CMPXCHG, sz)

TST_ATOMIC_SIZES (TST_CMPXCHG, cmpxchg_eq)
TST_ATOMIC_SIZES (TST_CMPXCHG, cmpxchg_ne)

  .align 16
  .type sig_trigger, @function
  .global sig_trigger
  .hidden sig_trigger
sig_trigger:
  subq	$8, %rsp
  pushq	%rsi
  pushq	%rdx
  call	sig_check_trigger
  popq	%rdx
  popq	%rsi
  addq	$8, %rsp

  testl	%eax, %eax
  jz	.lno_trigger

  movl	%eax, %edi
  jmp	eri_live_sigaction

.lno_trigger:
  ret
  .size sig_trigger, . - sig_trigger
