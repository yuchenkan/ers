/* vim: set ft=gas: */

#include <lib/util.h>
#include <live/tst/rtld/rtld-offsets.h>

  .text

ERI_FUNCTION (eri_start)
  pushq	%rdi
  call	start
  popq	%rdi
  movq	ERI_LIVE_RTLD_ARGS_RDX(%rdi), %rdx
  movq	ERI_LIVE_RTLD_ARGS_RSP(%rdi), %rsp
  movq	ERI_LIVE_RTLD_ARGS_RIP(%rdi), %rax
  jmp	*%rax
  ERI_END_FUNCTION (eri_start)
