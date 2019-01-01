/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

#include "public/impl.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_poll)

  movl	$__NR_poll, %eax
  xorq	%rdi, %rdi
  xorq	%rsi, %rsi
  movq	$1000 * 1000 * 1000, %rdx
  _ERS_SYSCALL

  ret
  .size tst_poll, . - tst_poll
