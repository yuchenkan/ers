/* vim: set ft=gas: */

#include <lib/util.h>

ERI_FUNCTION (eri_jump)
  movq	%rdi, %rsp
  movq	%rsi, %rax
  movq	%rdx, %rdi
  movq	%rcx, %rsi
  movq	%r8, %rdx
  jmp	*%rax
  ERI_END_FUNCTION (eri_jump)
