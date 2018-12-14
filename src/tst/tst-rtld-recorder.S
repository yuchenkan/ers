/* vim: set ft=gas: */

#include "rtld-offsets.h"

#include "lib/util.h"

  .text

  .align 16
  ERI_GLOBAL_HIDDEN (tst_start)
  .type tst_start, @function
tst_start:
  pushq	%rdi
  call	tst_rtld
  popq	%rdi
  movq	ERI_RTLD_RDX(%rdi), %rdx
  movq	ERI_RTLD_RSP(%rdi), %rsp
  movq	ERI_RTLD_RIP(%rdi), %rax
  popfq
  jmp	*%rax
  .size tst_start, . - tst_start
