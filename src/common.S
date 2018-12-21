/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (eri_daemon_clone)
  movq	%rsi, %r10
  movq	%rdi, %rsi
  movq	%rdx, -8(%rsi)

#define CLONE_FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM \
   | ERI_CLONE_CHILD_CLEARTID)

  movq	$CLONE_FLAGS, %rdi
  xorq	%rdx, %rdx
  xorq	%r8, %r8
  syscall
  jz	.ldaemon
  jl	.lerror
  ret
.ldaemon:
  movq	-8(%rsp), %rdi
  call	eri_daemon_loop
  movl	$__NR_exit, %eax
  xorq	%rdi, %rdi
  syscall
.lerror:
  ERI_ASSERT_FALSE
  .size eri_daemon_clone, . - eri_daemon_clone
