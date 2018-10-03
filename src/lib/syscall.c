#include "syscall.h"
#include "util-common.h"

asm ("  .text					\n\
  .align 16					\n\
  .type eri_sigreturn, @function		\n\
  .hidden eri_sigreturn				\n\
  .global eri_sigreturn				\n\
eri_sigreturn:					\n\
  movl	$" _ERS_STR (__NR_rt_sigreturn)", %eax	\n\
  syscall					\n\
  .size eri_sigreturn, .-eri_sigreturn		\n\
  .previous					\n"
);
