/* vim: set ft=gas: */

#include "lib/util.h"

  .section .text.start, "ax", @progbits

  .align 16
  ERI_GLOBAL_HIDDEN (eri_start)
  .type eri_start, @function
eri_start:
  movq	%rsp, %rdi
  movq	%rdx, %rsi
  pushfq
  jmp	eri_rtld
  .size eri_start, . - eri_start
