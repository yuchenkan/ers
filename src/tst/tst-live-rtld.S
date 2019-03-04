/* vim: set ft=gas: */

#include <tst/live-rtld/generated/public/live-rtld.h>

#define _ERS_LIVE_RTLD_H_INCLUDED
#include <public.h>

#include <lib/util.h>
#include <lib/syscall.h>

  .text

ERI_FUNCTION (start)
  movq	$0x12345678, %rdx
  ERS_INIT
  cmpq	$0x12345678, %rdx
  jne	.lerror

  movl	$__NR_exit, %eax
  xorq	%rdi, %rdi
  syscall

.lerror:
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (start)
