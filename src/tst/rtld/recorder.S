/* vim: set ft=gas: */

#include <rtld-offsets.h>

#include <lib/util.h>

  .text

ERI_FUNCTION (tst_start)
  pushq	%rdi
  call	tst_rtld
  popq	%rdi
  movq	ERI_RTLD_ARGS_RDX(%rdi), %rdx
  pushq	ERI_RTLD_ARGS_RFLAGS(%rdi)
  popfq
  movq	ERI_RTLD_ARGS_RSP(%rdi), %rsp
  movq	ERI_RTLD_ARGS_RIP(%rdi), %rax
  jmp	*%rax
  ERI_END_FUNCTION (tst_start)
