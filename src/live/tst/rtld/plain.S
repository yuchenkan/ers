/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/syscall-common.h>

  .text

ERI_FUNCTION (eri_start)
  movl	$__NR_exit, %eax
  movq	$1, %rdi
  syscall
  ERI_END_FUNCTION (eri_start)
