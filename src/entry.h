#ifndef ERI_ENTRY_H
#define ERI_ENTRY_H

#include <lib/util.h>

#ifndef ERI_BUILD_ENTRY_OFFSETS_H
# include <entry-offsets.h>
#endif

#define ERI_THREAD_ENTRY_SIG_HANDS(p) \
  p (SIG_HAND_SYSCALL, sig_hand_syscall)				\
  p (SIG_HAND_SYNC_ASYNC, sig_hand_sync_async)				\
  p (SIG_HAND_ATOMIC, sig_hand_atomic)

#define _ERI_ENTRY_TEXT_RIP_RELA(name, size, off) \
  ERI_PASTE (name, _text) - size + off(%rip)

#define ERI_ENTRY_TEXT(name, size, entry, offset) \
  .align 16;								\
ERI_SYMBOL (ERI_PASTE (name, _text))					\
ERI_SYMBOL (ERI_PASTE (name, _text_entry))				\
  leaq	_ERI_ENTRY_TEXT_RIP_RELA (name, size, 0), %rbx;			\
  jmp	*_ERI_ENTRY_TEXT_RIP_RELA (name, size, entry);			\
									\
  .align 16;								\
ERI_SYMBOL (ERI_PASTE (name, _text_return))				\
  movq	_ERI_ENTRY_TEXT_RIP_RELA (name, size,				\
		offset + ERI_THREAD_ENTRY_RBX), %rbx;			\
  jmp	*_ERI_ENTRY_TEXT_RIP_RELA (name, size,				\
		offset + ERI_THREAD_ENTRY_RET);				\
									\
ERI_SYMBOL (ERI_PASTE (name, _text_end))

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

#endif
