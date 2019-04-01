#ifndef ERI_COMMON_ENTRY_H
#define ERI_COMMON_ENTRY_H

#include <lib/util.h>
#include <lib/syscall.h>

#define ERI_ENTRY_THREAD_ENTRY_SIG_HANDS(p) \
  p (SIG_HAND_SYSCALL, sig_hand_syscall)				\
  p (SIG_HAND_SYNC_ASYNC, sig_hand_sync_async)				\
  p (SIG_HAND_ATOMIC, sig_hand_atomic)

/*
 * 16 general registers + rip + rflags =
 *   eri_scratch_registers + eri_extra_registers + rbx + rsp + rip
 */

#define ERI_ENTRY_FOREACH_SGREG_NO_RCX_RDX(p, ...) \
  p (RAX, rax, ##__VA_ARGS__)						\
  p (RDI, rdi, ##__VA_ARGS__)						\
  p (RSI, rsi, ##__VA_ARGS__)						\
  p (R8, r8, ##__VA_ARGS__)						\
  p (R9, r9, ##__VA_ARGS__)						\
  p (R10, r10, ##__VA_ARGS__)						\
  p (R11, r11, ##__VA_ARGS__)

#define ERI_ENTRY_FOREACH_SGREG_NO_RCX(p, ...) \
  ERI_ENTRY_FOREACH_SGREG_NO_RCX_RDX(p, ##__VA_ARGS__)			\
  p (RDX, rdx, ##__VA_ARGS__)

#define ERI_ENTRY_FOREACH_SGREG(p, ...) \
  ERI_ENTRY_FOREACH_SGREG_NO_RCX(p, ##__VA_ARGS__)			\
  p (RCX, rcx, ##__VA_ARGS__)

#define ERI_ENTRY_FOREACH_SREG(p, ...) \
  ERI_ENTRY_FOREACH_SGREG(p, ##__VA_ARGS__)				\
  p (RFLAGS, rflags, ##__VA_ARGS__)

#define ERI_ENTRY_FOREACH_EREG(p, ...) \
  p (RBP, rbp, ##__VA_ARGS__)						\
  p (R12, r12, ##__VA_ARGS__)						\
  p (R13, r13, ##__VA_ARGS__)						\
  p (R14, r14, ##__VA_ARGS__)						\
  p (R15, r15, ##__VA_ARGS__)

#ifndef __ASSEMBLER__

#include <stdint.h>

#include <lib/offset.h>

struct eri_entry_thread_entry
{
  uint64_t zero; /* so that %gs:0 is always zero */

  struct
    {
      uint8_t sig_hand;
      uint8_t args;
      uint16_t code;
    } op;

  uint64_t rbx;

  uint64_t call;
  uint64_t ret;

  uint64_t entry;

  union
    {
      struct
	{
	  uint64_t val;
	  uint64_t mem;

	  uint64_t ret;
	} atomic;
    };
};

#define _ERI_ENTRY_THREAD_ENTRY_OFFSET(ns, name, member) \
  ERI_DECLARE_OFFSET (ERI_PASTE (ns, _ENTRY_THREAD_ENTRY_), name,	\
		      struct eri_entry_thread_entry, member)

#define ERI_ENTRY_THREAD_ENTRY_OFFSETS(ns) \
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, OP, op);				\
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, RBX, rbx);			\
									\
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, CALL, call);			\
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, RET, ret);			\
									\
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, ENTRY, entry);			\
									\
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, ATOMIC_VAL, atomic.val);		\
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, ATOMIC_MEM, atomic.mem);		\
  _ERI_ENTRY_THREAD_ENTRY_OFFSET (ns, ATOMIC_RET, atomic.ret);		\

#define _ERI_ENTRY_DECLARE_REG(creg, reg)	uint64_t reg;

struct eri_entry_scratch_registers
{
  ERI_ENTRY_FOREACH_SREG (_ERI_ENTRY_DECLARE_REG)
};

struct eri_entry_extra_registers
{
  ERI_ENTRY_FOREACH_EREG (_ERI_ENTRY_DECLARE_REG)
};

struct eri_entry_thread_context
{
  uint64_t entry;
  uint64_t ret;

  uint64_t top;
  uint64_t rsp;

  struct eri_entry_scratch_registers sregs;
};

#define eri_sys_syscall_args_from_sregs(args, sregs) \
  do {									\
    struct eri_sys_syscall_args *_args = args;				\
    const struct eri_entry_scratch_registers *_sregs = sregs;		\
    _args->nr = _sregs->rax;						\
    _args->a[0] = _sregs->rdi;						\
    _args->a[1] = _sregs->rsi;						\
    _args->a[2] = _sregs->rdx;						\
    _args->a[3] = _sregs->r10;						\
    _args->a[4] = _sregs->r8;						\
    _args->a[5] = _sregs->r9;						\
  } while (0)

#endif

#ifndef ERI_ENTRY_BUILD_ENTRY_OFFSETS_H
# include <common/entry-offsets.h>
#endif

#define _ERI_ENTRY_THREAD_ENTRY_TEXT_RIP_RELA(name, size, off) \
  ERI_PASTE (name, _text) - (size) + (off)(%rip)

#define ERI_ENTRY_THREAD_ENTRY_TEXT(name, size, entry, offset) \
  .align 16;								\
ERI_SYMBOL (ERI_PASTE (name, _text))					\
ERI_SYMBOL (ERI_PASTE (name, _text_entry))				\
  leaq	_ERI_ENTRY_THREAD_ENTRY_TEXT_RIP_RELA (name, size, 0), %rbx;	\
  jmp	*_ERI_ENTRY_THREAD_ENTRY_TEXT_RIP_RELA (name, size, entry);	\
									\
  .align 16;								\
ERI_SYMBOL (ERI_PASTE (name, _text_return))				\
  movq	_ERI_ENTRY_THREAD_ENTRY_TEXT_RIP_RELA (name, size,		\
		(offset) + ERI_ENTRY_THREAD_ENTRY_RBX), %rbx;		\
  jmp	*_ERI_ENTRY_THREAD_ENTRY_TEXT_RIP_RELA (name, size,		\
		(offset) + ERI_ENTRY_THREAD_ENTRY_RET);			\
									\
ERI_SYMBOL (ERI_PASTE (name, _text_end))

#define _ERI_ENTRY_THREAD_CONTEXT_ENTRY_SAVE_SGREG(creg, reg, off) \
  movq	%reg, (off) + ERI_PASTE (ERI_ENTRY_THREAD_CONTEXT_SREGS_, creg)(%rbx);
#define _ERI_ENTRY_THREAD_CONTEXT_ENTRY_RESTORE_SGREG(creg, reg, off) \
  movq	(off) + ERI_PASTE (ERI_ENTRY_THREAD_CONTEXT_SREGS_, creg)(%rbx), %reg;

#define ERI_ENTRY_THREAD_CONTEXT_ENTRY(name, offset) \
ERI_FUNCTION (name)							\
  movq	%rsp, (offset) + ERI_ENTRY_THREAD_CONTEXT_RSP(%rbx);		\
  movq	(offset) + ERI_ENTRY_THREAD_CONTEXT_TOP(%rbx), %rsp;		\
									\
  pushfq;								\
  popq	(offset) + ERI_ENTRY_THREAD_CONTEXT_SREGS_RFLAGS(%rbx);		\
									\
  pushq	$0;								\
  popfq;								\
									\
  ERI_ENTRY_FOREACH_SGREG (						\
		_ERI_ENTRY_THREAD_CONTEXT_ENTRY_SAVE_SGREG, offset)

#define ERI_ENTRY_THREAD_CONTEXT_RESTORE_NO_RCX(offset) \
  ERI_ENTRY_FOREACH_SGREG_NO_RCX (					\
		_ERI_ENTRY_THREAD_CONTEXT_ENTRY_RESTORE_SGREG, offset)	\
  pushq	(offset) + ERI_ENTRY_THREAD_CONTEXT_SREGS_RFLAGS(%rbx);		\
  popfq;								\
  movq	(offset) + ERI_ENTRY_THREAD_CONTEXT_RSP(%rbx), %rsp

#define ERI_ENTRY_THREAD_CONTEXT_RESTORE(offset) \
  _ERI_ENTRY_THREAD_CONTEXT_ENTRY_RESTORE_SGREG (RCX, rcx, offset)	\
  ERI_ENTRY_THREAD_CONTEXT_RESTORE_NO_RCX (offset)

#define _ERI_ENTRY_SAVE_EREG(creg, reg, off) \
  movq	%reg, (off) + ERI_PASTE (ERI_ENTRY_EXTRA_REGISTERS_, creg)(%rbx);
#define _ERI_ENTRY_RESTORE_EREG(creg, reg, off) \
  movq	(off) + ERI_PASTE (ERI_ENTRY_EXTRA_REGISTERS_, creg)(%rbx), %reg;

#define ERI_ENTRY_SAVE_EREGS(offset) \
  ERI_ENTRY_FOREACH_EREG (_ERI_ENTRY_SAVE_EREG, offset)
#define ERI_ENTRY_RESTORE_EREGS(offset) \
  ERI_ENTRY_FOREACH_EREG (_ERI_ENTRY_RESTORE_EREG, offset)

#define ERI_ENTRY_SYSCALL_MAY_SAVE_EREGS(offset, prefix) \
  cmpl	$__NR_clone, %eax;						\
  je	ERI_PASTE2 (.L, prefix, _extra_save);				\
  cmpl	$__NR_rt_sigreturn, %eax;					\
  je	ERI_PASTE2 (.L, prefix, _extra_save);				\
  jmp	ERI_PASTE2 (.L, prefix, _no_extra_save);			\
ERI_PASTE2 (.L, prefix, _extra_save):					\
  ERI_ENTRY_FOREACH_EREG (_ERI_ENTRY_SAVE_EREG, offset)			\
ERI_PASTE2 (.L, prefix, _no_extra_save):

#define ERI_ENTRY_SYSCALL_MAY_RESTORE_EREGS(offset, prefix) \
  testq	%rax, %rax;							\
  jz	ERI_PASTE2 (.L, prefix, _no_extra_restore);			\
  cmpq	$1, %rax;							\
  je	ERI_PASTE2 (.L, prefix, _extra_restore);			\
  movq	%rax, %rbx; /* clone child start */				\
ERI_PASTE2 (.L, prefix, _extra_restore):				\
  ERI_ENTRY_FOREACH_EREG (_ERI_ENTRY_RESTORE_EREG, offset)		\
ERI_PASTE2 (.L, prefix, _no_extra_restore):

#define ERI_ENTRY_DEFINE_COPY_USER_LABEL(pfx, op, sfx) \
  ERI_PASTE2 (ERI_PASTE2 (.L, pfx, _copy_), op, sfx)
#define _ERI_ENTRY_DEFINE_COPY_USER_SET_ACCESS(pfx, op) \
  ERI_MOV_LM (ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, op, _user),	\
	      THREAD_CONTEXT_ACCESS(%rdi), %rax);			\
  ERI_MOV_LM (ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, op, _user_fault),	\
	      THREAD_CONTEXT_ACCESS_FAULT(%rdi), %rax)

#define _ERI_ENTRY_DEFINE_COPY_USER_RETURN(res) \
  movq	$0, THREAD_CONTEXT_ACCESS(%rdi);				\
  movb	$res, %al;							\
  ret

#define ERI_ENTRY_COPY_USER(pfx, name, op, ...) \
  _ERI_ENTRY_DEFINE_COPY_USER_SET_ACCESS (pfx, name);			\
ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, name, _loop):			\
  op (__VA_ARGS__);							\
  loop	ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, name, _loop);		\
									\
  _ERI_ENTRY_DEFINE_COPY_USER_RETURN (1);				\
									\
ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, name, _user_fault):		\
  _ERI_ENTRY_DEFINE_COPY_USER_RETURN (0)

#define _ERI_ENTRY_COPY_LOAD_USER(pfx) \
ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, load, _user):			\
  movb	(%rdx), %al;							\
  movb	%al, (%rsi);							\
  incq	%rdx;								\
  incq	%rsi

#define _ERI_ENTRY_COPY_STORE_USER(pfx) \
  movb	(%rdx), %al;							\
ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, store, _user):			\
  movb	%al, (%rsi);							\
  incq	%rdx;								\
  incq	%rsi
 
#define _ERI_ENTRY_DEFINE_COPY_USER(pfx) \
ERI_FUNCTION (ERI_PASTE (pfx, _copy_from_user))				\
  .cfi_startproc;							\
  ERI_ENTRY_COPY_USER (pfx, load, _ERI_ENTRY_COPY_LOAD_USER, pfx);	\
  .cfi_endproc;								\
  ERI_END_FUNCTION (ERI_PASTE (pfx, _copy_from_user));			\
									\
ERI_FUNCTION (ERI_PASTE (pfx, _copy_to_user))				\
  .cfi_startproc;							\
  ERI_ENTRY_COPY_USER (pfx, store, _ERI_ENTRY_COPY_STORE_USER, pfx);	\
  .cfi_endproc;								\
  ERI_END_FUNCTION (ERI_PASTE (pfx, _copy_to_user))

#define _ERI_ENTRY_COPY_READ_USER() \
ERI_ENTRY_DEFINE_COPY_USER_LABEL (pfx, read, _user):			\
  movb	(%rsi), %al;							\
  incq	%rsi

#define _ERI_ENTRY_DEFINE_ACCESS_USER(pfx, access) \
ERI_FUNCTION (ERI_PASTE (pfx, _read_user))				\
  .cfi_startproc;							\
  movq	%rdx, %rcx;							\
  ERI_ENTRY_COPY_USER (pfx, access, read,				\
		       _ERI_ENTRY_COPY_READ_USER);			\
  .cfi_endproc;								\
  ERI_END_FUNCTION (ERI_PASTE (pfx, _read_user))

#define ERI_ENTRY_DEFINE_DO_COPY_USER() \
  _ERI_ENTRY_DEFINE_COPY_USER (do);

#ifndef __ASSEMBLER__

#define eri_entry_thread_entry_text_size(name) \
  ({ extern uint8_t ERI_PASTE (name, _text)[];				\
     extern uint8_t ERI_PASTE (name, _text_end)[];			\
     ERI_PASTE (name, _text_end) - ERI_PASTE (name, _text); })

#define eri_entry_thread_entry_text(name, th_text, text) \
  ({ extern uint8_t ERI_PASTE (name, _text)[];				\
     extern uint8_t ERI_PASTE2 (name, _text_, text)[];			\
     (uint64_t) (th_text) + ERI_PASTE2 (name, _text_, text)		\
				 - ERI_PASTE (name, _text); })

#define eri_entry_thread_entry_copy_text(name, th_text) \
  do {									\
    extern uint8_t ERI_PASTE (name, _text)[];				\
    uint64_t _size = eri_entry_thread_entry_text_size (name);		\
    eri_memcpy ((void *) (th_text), ERI_PASTE (name, _text), _size);	\
  } while (0)

#define eri_entry_init(ent, ctx, text, th_text, e, t) \
  do {									\
    struct eri_entry_thread_entry *_ent = ent;				\
    struct eri_entry_thread_context *_ctx = ctx;			\
    uint8_t *_th_text = th_text;					\
    eri_entry_thread_entry_copy_text (text, _th_text);			\
    _ent->zero = 0;							\
    _ent->entry = eri_entry_thread_entry_text(text, _th_text, entry);	\
    _ctx->entry = (uint64_t) (e);					\
    _ctx->ret = eri_entry_thread_entry_text(text, _th_text, return);	\
    _ctx->top = (uint64_t) (t);						\
  } while (0)

#define ERI_ENTRY_DECLARE_DO_COPY_USER() \
uint8_t do_copy_from_user (struct thread_context *th_ctx,		\
			   void *dst, const void *src, uint64_t size);	\
uint8_t do_copy_to_user (struct thread_context *th_ctx,			\
			 void *dst, const void *src, uint64_t size);

#endif

#endif
