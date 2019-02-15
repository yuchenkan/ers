/* vim: set ft=gas: */

#include <tst/rtld/generated/public/rtld.h>

#include <public/impl.h>

#include <lib/util.h>
#include <lib/syscall.h>

  .text

ERI_FUNCTION (start)
  movq	$0x12345678, %rdx
  _ERS_INIT
  cmpq	$0x12345678, %rdx
  jne	.lerror

  movl	$__NR_exit, %eax
  xorq	%rdi, %rdi
  syscall

.lerror:
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (start)
