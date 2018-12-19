/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_start)
  call	tst_main
  movq	%rax, %rdi
  movl	$__NR_exit, %eax
  syscall
  .size tst_start, . - tst_start

