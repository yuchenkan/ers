#include <entry.h>

#include <lib/util.h>
#include <lib/offset.h>

#define THREAD_ENTRY_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (_ERS_THREAD_ENTRY_, name,				\
		      struct eri_thread_entry, member)

enum
{
#define SIG_HAND_ENUM(chand, hand)	chand,
  ERI_THREAD_ENTRY_SIG_HANDS (SIG_HAND_ENUM)
};

void
declare (void)
{
  THREAD_ENTRY_OFFSET (OP, op);
  THREAD_ENTRY_OFFSET (RBX, rbx);

  THREAD_ENTRY_OFFSET (CALL, call);
  THREAD_ENTRY_OFFSET (RET, ret);

  THREAD_ENTRY_OFFSET (ENTRY, entry);

  THREAD_ENTRY_OFFSET (ATOMIC_VAL, atomic.val);
  THREAD_ENTRY_OFFSET (ATOMIC_MEM, atomic.mem);
  THREAD_ENTRY_OFFSET (ATOMIC_RET, atomic.ret);

#define SIG_HAND_SYMBOL(chand, hand) \
  ERI_DECLARE_SYMBOL (ERI_PASTE (_ERS_, chand), chand);

  ERI_THREAD_ENTRY_SIG_HANDS (SIG_HAND_SYMBOL)
}
