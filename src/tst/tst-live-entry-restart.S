/* vim: set ft=gas: */

#include "public/impl.h"

#include "lib/util.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_raw_syscall)
ERI_GLOBAL_HIDDEN (tst_raw_syscall_enter)
  syscall
ERI_GLOBAL_HIDDEN (tst_raw_syscall_leave)
  ret

ERI_GLOBAL_HIDDEN_FUNCTION (tst_raw_sync_async)
  nop
ERI_GLOBAL_HIDDEN (tst_raw_sync_async_leave)
  ret

ERI_GLOBAL_HIDDEN_FUNCTION (tst_syscall)
ERI_GLOBAL_HIDDEN (tst_syscall_enter)
  _ERS_SYSCALL
ERI_GLOBAL_HIDDEN (tst_syscall_leave)
  ret

ERI_GLOBAL_HIDDEN_FUNCTION (tst_sync_async)
ERI_GLOBAL_HIDDEN (tst_sync_async_enter)
  _ERS_SYNC_ASYNC (nop)
ERI_GLOBAL_HIDDEN (tst_sync_async_leave)
  ret
