#include "lib/offset.h"
#include "rtld.h"

#define RTLD_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_RTLD_, name, struct eri_rtld, member)

void
declare (void)
{
  RTLD_OFFSET (RDX, rdx);
  RTLD_OFFSET (RSP, rsp);
  RTLD_OFFSET (RIP, rip);
  RTLD_OFFSET (SIG_MASK_ALL, sig_mask.mask_all);
  RTLD_OFFSET (SIG_MASK, sig_mask.mask);
}
