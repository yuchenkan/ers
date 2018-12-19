/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (eri_sigreturn)
  movl	$__NR_rt_sigreturn, %eax
  syscall
  .size eri_sigreturn, .-eri_sigreturn
