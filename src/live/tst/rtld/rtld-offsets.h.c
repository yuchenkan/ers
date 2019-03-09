#include <lib/offset.h>
#include <live/rtld.h>

#define RTLD_ARGS_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_LIVE_RTLD_ARGS_, name,			\
		      struct eri_live_rtld_args, member)

void
declare (void)
{
  RTLD_ARGS_OFFSET (RDX, rdx);
  RTLD_ARGS_OFFSET (RSP, rsp);
  RTLD_ARGS_OFFSET (RIP, rip);
}
