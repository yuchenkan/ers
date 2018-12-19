/* vim: set ft=gas: */

#include "rtld-offsets.h"

#include "lib/util.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_start)
  pushq	%rdi
  call	tst_rtld
  popq	%rdi
  movq	ERI_RTLD_RDX(%rdi), %rdx
  movq	ERI_RTLD_RSP(%rdi), %rsp
  movq	ERI_RTLD_RIP(%rdi), %rax
  popfq
  jmp	*%rax
  .size tst_start, . - tst_start
