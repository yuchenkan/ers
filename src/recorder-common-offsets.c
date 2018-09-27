#include "recorder-common.h"
#include "lib/offset.h"

#define REC_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (_ERS_REC_, name, struct ers_recorder, member)

void
declare (void)
{
  REC_OFFSET (INIT_PROCESS, init_process);
  REC_OFFSET (SETUP_TLS, setup_tls);
  REC_OFFSET (SYSCALL, syscall);
  REC_OFFSET (ATOMIC_LOCK, atomic_lock);
  REC_OFFSET (ATOMIC_UNLOCK, atomic_unlock);
  REC_OFFSET (ATOMIC_BARRIER, atomic_barrier);
  REC_OFFSET (ANALYSIS, analysis);
}
