#ifndef ERI_ENTRY_H
#define ERI_ENTRY_H

#include <stdint.h>

#define ERI_THREAD_ENTRY_SIG_HANDS(p) \
  p (SIG_HAND_SYSCALL, sig_hand_syscall)				\
  p (SIG_HAND_SYNC_ASYNC, sig_hand_sync_async)				\
  p (SIG_HAND_ATOMIC, sig_hand_atomic)

struct eri_thread_entry
{
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

#endif
