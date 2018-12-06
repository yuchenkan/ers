#include "lib/syscall.h"

  .text
  .align 16
  .type eri_sigreturn, @function
  .global eri_sigreturn
  .hidden eri_sigreturn
eri_sigreturn:
  movl	$__NR_rt_sigreturn, %eax
  syscall
  .size eri_sigreturn, .-eri_sigreturn
