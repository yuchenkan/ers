/* vim: set ft=gas: */

#include "lib/util.h"

  .section .text.start, "ax", @progbits

ERI_GLOBAL_HIDDEN_FUNCTION (eri_start)
  movq	%rsp, %rdi
  movq	%rdx, %rsi
  pushfq
  jmp	eri_rtld
  .size eri_start, . - eri_start
