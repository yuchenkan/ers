/* vim: set ft=gas: */

#include <entry.h>
#include <lib/util.h>

#include <public/common.h>
#include <replay/thread-local-offsets.h>

#define PASTE(x, y)	ERI_PASTE (x, y)
#define PASTE2(x, y, z)	ERI_PASTE2 (x, y, z)

#define TC(name)	PASTE (THREAD_CONTEXT_, name)
#define TCC(name)	TC (PASTE (CTX_, name))

  .section .rodata

ERI_ENTRY_THREAD_ENTRY_TEXT (thread_context, TC (SIZE), TCC (ENTRY), TC (EXT))

  .text

#define TH_CALL(fn) \
  movq	TC (TH)(%rbx), %rdi;						\
  call	fn

ERI_FUNCTION (main)
  movq	%rdi, %rbx
  movq	TCC (TOP)(%rbx), %rsp
  TH_CALL (start_main)

  /* XXX: ensure eregs all zero */
  ERI_ENTRY_THREAD_CONTEXT_RESTORE (TC (CTX))
  jmp	*TCC (RET)(%rbx)
  ERI_END_FUNCTION (start_main)

ERI_ENTRY_THREAD_CONTEXT_ENTRY (entry, TC (CTX))

  ERI_ENTRY_SAVE_EREGS (TC (EREGS))

  TH_CALL (relax)

  ERI_ENTRY_SYSCALL_MAY_RESTORE_EREGS (TC (EREGS), entry)

  ERI_ENTRY_THREAD_CONTEXT_RESTORE (TC (CTX))
  jmp	*TCC (RET)(%rbx)

  ERI_END_FUNCTION (entry)

#define IF_ATOMIC_SIZE(sz, size, name) \
  cmpb	$PASTE (_ERS_ATOMIC_SIZE_, sz),	%size (sz);			\
  je	PASTE2 (.L, name, sz);

#define ATOMIC_SIZE(sz, name, op, ...) \
PASTE2 (.L, name, sz):							\
  op (sz, ##__VA_ARGS__);						\
  ret;

#define DEFINE_ATOMIC_FUNCTION(name, size, op, ...) \
ERI_FUNCTION (name)							\
  ERI_FOREACH_REG_SIZE (IF_ATOMIC_SIZE, size, name)			\
  ERI_ASSERT_FALSE;							\
ERI_FOREACH_REG_SIZE (ATOMIC_SIZE, name, op, ##__VA_ARGS__)		\
  ERI_END_FUNCTION (name)

#define ATOMIC_ACCESS_LABEL(sz, name) \
  PASTE2 (PASTE2 (.Ldo_atomic_, name, _user), sz, _access)

#define ATOMIC_ACCESS(sz, cname, name) \
  ERI_MOV_LM (ATOMIC_ACCESS_LABEL (sz, name),				\
	      TC (ATOMIC_ACCESS_FAULT)(%rdi));				\
ATOMIC_ACCESS_LABEL (sz, name):						\
  PASTE2 (DO_ATOMIC_, cname, _USER) (sz);				\
  movq	$0, TC (ATOMIC_ACCESS_FAULT)(%rdi)

#define DO_ATOMIC_READ_USER(sz) \
  PASTE (mov, sz)	(%rsi), %ERI_RAX (sz)
#define DO_ATOMIC_READ_WRITE_USER(sz) \
  PASTE (or, sz)	$0, (%rsi)

#define DEFINE_ATOMIC_ACCESS_FUNCTION(cname, name) \
DEFINE_ATOMIC_FUNCTION (PASTE2 (do_atomic_, name, _user), ERI_RDX,	\
			ATOMIC_ACCESS, cname, name)

DEFINE_ATOMIC_ACCESS_FUNCTION (READ, read)
DEFINE_ATOMIC_ACCESS_FUNCTION (READ_WRITE, read_write)

#define ATOMIC_STORE(sz) \
  PASTE (mov, sz)	%ERI_RDX (sz), (%rsi)

#define ATOMIC_INC_DEC(sz, inc) \
  pushq	(%rdx);								\
  popfq;								\
  PASTE (inc, sz)	(%rsi);						\
  pushfq;								\
  popq	(%rdx)

#define ATOMIC_CMPXCHG_REGS(sz) \
  movq	(%rsi), %rax;							\
  pushq	(%rdx);								\
  popfq;								\
  PASTE (cmpxchg, sz)	%ERI_R11 (sz), %ERI_RCX (sz);			\
  pushfq;								\
  popq	(%rdx);								\
  movq	%rax, (%rsi)

DEFINE_ATOMIC_FUNCTION (atomic_store, ERI_RDI, ATOMIC_STORE)
DEFINE_ATOMIC_FUNCTION (atomic_inc, ERI_RDI, ATOMIC_INC_DEC, inc)
DEFINE_ATOMIC_FUNCTION (atomic_dec, ERI_RDI, ATOMIC_INC_DEC, dec)
DEFINE_ATOMIC_FUNCTION (atomic_cmpxchg_regs, ERI_RDI, ATOMIC_CMPXCHG_REGS)
