#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/util.h>
#include <live/tst/tst-sig-race.h>

TST_LIVE_SIG_RACE_DEFINE_TST (ERI_EMPTY,
			      tst_assert_sys_sigprocmask_all (), 0, 0)
