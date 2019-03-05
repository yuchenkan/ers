/* vim: set ft=gas: */

#include <lib/util.h>

  .section .text.start, "ax", @progbits

ERI_FUNCTION (eri_start)
  movq	%rsp, %rdi
  movq	%rdx, %rsi
  pushfq
  popq	%rdx
  jmp	rtld
  ERI_END_FUNCTION (eri_start)
