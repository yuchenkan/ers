/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (eri_daemon_clone)
  movq	$0, (%rdi)

  movl	$__NR_futex, %eax
  movq	$ERI_FUTEX_WAKE, %rsi
  movq	$1, %rdx
  syscall
  cmpq	$-4096, %rax
  ja	.lerror
1:
  jmp	1b
.lerror:
  ERI_ASSERT_FALSE
  .size eri_daemon_clone, . - eri_daemon_clone
