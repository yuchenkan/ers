/* vim: set ft=gas: */

#include "public/impl.h"

#include "lib/util.h"
#include "lib/syscall.h"

  .text

  .align 16
  .global start
  .type start, @function
start:
  pushq	$0x12345678
  pushq	$0x12345678
  _ERS_INIT
  cmpl	$0x12345678, (%rsp)
  jne	.lerror
  cmpl	$0x12345678, 8(%rsp)
  jne	.lerror

  movl	$__NR_exit, %eax
  xorq	%rdi, %rdi
  syscall

.lerror:
  ERI_ASSERT_FALSE
