/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/syscall.h>

ERI_FUNCTION (eri_assert_lock)
  .cfi_startproc
1:
  movl	$1, %eax
  xchgl	%eax, (%rdi) 
  testq	%rax, %rax
  jz	2f
  movl	$__NR_futex, %eax
  movq	$ERI_FUTEX_WAIT, %rsi
  movq	$1, %rdx
  xorq	%r10, %r10
  syscall
  cmpq	$ERI_EAGAIN, %rax
  je	1b
  cmpq	$ERI_EINTR, %rax
  je	1b
  cmpq	$-4096, %rax
  jbe	1b
  ERI_ASSERT_FALSE
2:
  ret
  .cfi_endproc
  ERI_END_FUNCTION (eri_assert_lock)

ERI_FUNCTION (eri_assert_unlock)
  .cfi_startproc
  movl	$0, (%rdi)
  movl	$__NR_futex, %eax
  movq	$ERI_FUTEX_WAKE, %rsi
  movq	$1, %rdx
  syscall
  cmpq	$-4096, %rax
  ja	1f
  ret
1:
  ERI_ASSERT_FALSE
  .cfi_endproc
  ERI_END_FUNCTION (eri_assert_unlock)
