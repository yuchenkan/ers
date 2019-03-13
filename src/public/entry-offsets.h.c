#define ERI_ENTRY_BUILD_ENTRY_OFFSETS_H
#include <entry.h>
#include <lib/util.h>
#include <lib/offset.h>

enum
{
#define SIG_HAND_ENUM(chand, hand)	chand,
  ERI_ENTRY_THREAD_ENTRY_SIG_HANDS (SIG_HAND_ENUM)
};

void
declare (void)
{
  ERI_ENTRY_THREAD_ENTRY_OFFSETS (_ERS)

#define SIG_HAND_SYMBOL(chand, hand) \
  ERI_DECLARE_SYMBOL (ERI_PASTE (_ERS_, chand), chand);

  ERI_ENTRY_THREAD_ENTRY_SIG_HANDS (SIG_HAND_SYMBOL)
}
