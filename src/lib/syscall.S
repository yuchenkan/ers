/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text
  .align 16
  ERI_GLOBAL_HIDDEN (eri_sigreturn)
  .type eri_sigreturn, @function
eri_sigreturn:
  movl	$__NR_rt_sigreturn, %eax
  syscall
  .size eri_sigreturn, .-eri_sigreturn
