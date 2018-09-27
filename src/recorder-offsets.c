#include "recorder.h"
#include "lib/offset.h"
#include "lib/util.h"

#define CLONE_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_CLONE_DESC_, name, struct eri_clone_desc, member)

void
declare (void)
{
  CLONE_OFFSET (CHILD, child);
  CLONE_OFFSET (FLAGS, flags);
  CLONE_OFFSET (CSTACK, cstack);
  CLONE_OFFSET (PTID, ptid);
  CLONE_OFFSET (CTID, ctid);
  CLONE_OFFSET (TP, tp);
  CLONE_OFFSET (REPLAY_RESULT, replay_result);

  ERI_DECLARE_SYMBOL (ERI_CLONE_DESC_SIZE16,
		      eri_round_up (sizeof (struct eri_clone_desc), 16));
}
