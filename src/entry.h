#ifndef ERI_ENTRY_H
#define ERI_ENTRY_H

#include <lib/util.h>

#define ERI_THREAD_ENTRY_SIG_HANDS(p) \
  p (SIG_HAND_SYSCALL, sig_hand_syscall)				\
  p (SIG_HAND_SYNC_ASYNC, sig_hand_sync_async)				\
  p (SIG_HAND_ATOMIC, sig_hand_atomic)

#ifndef __ASSEMBLER__

#include <stdint.h>

struct eri_thread_entry
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

/*
 * 16 general registers + rip + rflags =
 *   eri_scratch_registers + eri_extra_registers + rbx + rsp + rip
 */

struct eri_scratch_registers
{
  uint64_t rax;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rdx;
  uint64_t rcx;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t rflags;
};

struct eri_extra_registers
{
  uint64_t rbp;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
};

struct eri_thread_context
{
  uint64_t entry;
  uint64_t ret;

  uint64_t top;
  uint64_t rsp;

  struct eri_scratch_registers sregs;
};

#include <lib/offset.h>

#define _ERI_THREAD_ENTRY_OFFSET(ns, name, member) \
  ERI_DECLARE_OFFSET (ERI_PASTE (ns, _THREAD_ENTRY_), name,		\
		      struct eri_thread_entry, member)

#define ERI_THREAD_ENTRY_OFFSETS(ns) \
  _ERI_THREAD_ENTRY_OFFSET (ns, OP, op);				\
  _ERI_THREAD_ENTRY_OFFSET (ns, RBX, rbx);				\
									\
  _ERI_THREAD_ENTRY_OFFSET (ns, CALL, call);				\
  _ERI_THREAD_ENTRY_OFFSET (ns, RET, ret);				\
									\
  _ERI_THREAD_ENTRY_OFFSET (ns, ENTRY, entry);				\
									\
  _ERI_THREAD_ENTRY_OFFSET (ns, ATOMIC_VAL, atomic.val);		\
  _ERI_THREAD_ENTRY_OFFSET (ns, ATOMIC_MEM, atomic.mem);		\
  _ERI_THREAD_ENTRY_OFFSET (ns, ATOMIC_RET, atomic.ret);		\

#endif

#ifndef ERI_BUILD_ENTRY_OFFSETS_H
# include <entry-offsets.h>
#endif

#define _ERI_THREAD_ENTRY_TEXT_RIP_RELA(name, size, off) \
  ERI_PASTE (name, _text) - (size) + (off)(%rip)

#define ERI_THREAD_ENTRY_TEXT(name, size, entry, offset) \
  .align 16;								\
ERI_SYMBOL (ERI_PASTE (name, _text))					\
ERI_SYMBOL (ERI_PASTE (name, _text_entry))				\
  leaq	_ERI_THREAD_ENTRY_TEXT_RIP_RELA (name, size, 0), %rbx;		\
  jmp	*_ERI_THREAD_ENTRY_TEXT_RIP_RELA (name, size, entry);		\
									\
  .align 16;								\
ERI_SYMBOL (ERI_PASTE (name, _text_return))				\
  movq	_ERI_THREAD_ENTRY_TEXT_RIP_RELA (name, size,			\
		(offset) + ERI_THREAD_ENTRY_RBX), %rbx;			\
  jmp	*_ERI_THREAD_ENTRY_TEXT_RIP_RELA (name, size,			\
		(offset) + ERI_THREAD_ENTRY_RET);			\
									\
ERI_SYMBOL (ERI_PASTE (name, _text_end))

#define ERI_THREAD_CONTEXT_ENTRY(name, offset)				\
ERI_FUNCTION (name)							\
  movq	%rsp, (offset) + ERI_THREAD_CONTEXT_RSP(%rbx);			\
  movq	(offset) + ERI_THREAD_CONTEXT_TOP(%rbx), %rsp;			\
									\
  pushfq;								\
  popq	(offset) + ERI_THREAD_CONTEXT_SREGS_RFLAGS(%rbx);		\
									\
  pushq	$0;								\
  popfq;								\
									\
  movq	%rax, (offset) + ERI_THREAD_CONTEXT_SREGS_RAX(%rbx);		\
  movq	%rdi, (offset) + ERI_THREAD_CONTEXT_SREGS_RDI(%rbx);		\
  movq	%rsi, (offset) + ERI_THREAD_CONTEXT_SREGS_RSI(%rbx);		\
  movq	%rdx, (offset) + ERI_THREAD_CONTEXT_SREGS_RDX(%rbx);		\
  movq	%rcx, (offset) + ERI_THREAD_CONTEXT_SREGS_RCX(%rbx);		\
  movq	%r8, (offset) + ERI_THREAD_CONTEXT_SREGS_R8(%rbx);		\
  movq	%r9, (offset) + ERI_THREAD_CONTEXT_SREGS_R9(%rbx);		\
  movq	%r10, (offset) + ERI_THREAD_CONTEXT_SREGS_R10(%rbx);		\
  movq	%r11, (offset) + ERI_THREAD_CONTEXT_SREGS_R11(%rbx)

#ifndef __ASSEMBLER__

#define eri_thread_entry_text_size(name) \
  ({ extern uint8_t ERI_PASTE (name, _text)[];				\
     extern uint8_t ERI_PASTE (name, _text_end)[];			\
     ERI_PASTE (name, _text_end) - ERI_PASTE (name, _text); })

#define eri_thread_entry_text(name, th_text, text) \
  ({ extern uint8_t ERI_PASTE (name, _text)[];				\
     extern uint8_t ERI_PASTE2 (name, _text_, text)[];			\
     (uint64_t) (th_text) + ERI_PASTE2 (name, _text_, text)		\
				 - ERI_PASTE (name, _text); })

#define eri_thread_entry_copy_text(name, th_text) \
  do {									\
    extern uint8_t ERI_PASTE (name, _text)[];				\
    uint64_t _size = eri_thread_entry_text_size (name);			\
    eri_memcpy ((void *) (th_text), ERI_PASTE (name, _text), _size);	\
  } while (0)

#endif

#endif
