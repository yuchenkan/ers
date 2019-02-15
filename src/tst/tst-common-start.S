/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/syscall.h>

  .text

ERI_FUNCTION (tst_start)
  call	tst_main
  movl	%eax, %edi
  movl	$__NR_exit, %eax
  syscall
  ERI_END_FUNCTION (tst_start)
