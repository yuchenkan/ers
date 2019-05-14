#ifndef ERI_LIB_LOCK_H
#define ERI_LIB_LOCK_H

#ifndef ERI_APPLY_ERS
#include <lib/lock-specific.h>
#else

#include <tst/tst-lock-specific.h>

#define eri_assert_lock	tst_assert_lock
#define eri_assert_unlock	tst_assert_unlock

#endif

#endif
