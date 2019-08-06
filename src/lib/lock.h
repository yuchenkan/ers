#ifndef ERI_LIB_LOCK_H
#define ERI_LIB_LOCK_H

#ifndef ERI_APPLY_ERS
#include <lib/lock-specific.h>
#else

#include <tst/tst-lock-specific.h>

#define _eri_assert_lock	_tst_assert_lock
#define _eri_assert_unlock	_tst_assert_unlock
#define eri_assert_lock	tst_assert_lock
#define eri_assert_unlock	tst_assert_unlock

#define _eri_assert_rlock	_tst_assert_rlock
#define _eri_assert_wlock	_tst_assert_wlock
#define _eri_assert_runlock	_tst_assert_runlock
#define _eri_assert_wunlock	_tst_assert_wunlock
#define eri_assert_rlock	tst_assert_rlock
#define eri_assert_wlock	tst_assert_wlock
#define eri_assert_runlock	tst_assert_runlock
#define eri_assert_wunlock	tst_assert_wunlock

#endif

#endif
