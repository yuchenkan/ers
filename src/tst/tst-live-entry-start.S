/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

  .align 16
  ERI_GLOBAL_HIDDEN (tst_start)
  ERI_GLOBAL_HIDDEN (tst_continue)
  .type tst_start, @function
tst_start:
  pushq	$0x12345678
  pushq	$0x12345678
  movq	%rsp, %rdi
  movq	$0x12345678, %rsi
  leaq	tst_continue(%rip), %rdx
  pushq	$0x203
  orq	$ERI_TRACE_FLAG_MASK, (%rsp)
  jmp	tst_rtld

tst_continue:
  cmpb	$1, sigtrap_triggered
  jne	.lerror
  movq	%rsp, %rdi
  movq	$0x12345678, %rsi
  leaq	.lexit(%rip), %rdx
  pushq	$0x203
  jmp	tst_rtld

.lexit:
  cmpb	$1, sigtrap_triggered
  jne	.lerror

#define ASSERT_ZERO(reg) \
  testq	reg, reg;						\
  jnz	.lerror

  ASSERT_ZERO (%rax)
  ASSERT_ZERO (%rbx)
  ASSERT_ZERO (%rcx)
  ASSERT_ZERO (%rdi)
  ASSERT_ZERO (%rsi)
  ASSERT_ZERO (%rbp)
  ASSERT_ZERO (%r8)
  ASSERT_ZERO (%r9)
  ASSERT_ZERO (%r10)
  ASSERT_ZERO (%r11)
  ASSERT_ZERO (%r12)
  ASSERT_ZERO (%r13)
  ASSERT_ZERO (%r14)
  ASSERT_ZERO (%r15)

  cmpq	$0x12345678, %rdx
  jne	.lerror
  cmpq	$0x12345678, 8(%rsp)
  jne	.lerror
  cmpq	$0x12345678, (%rsp)
  jne	.lerror
  cmpq	$0, -8(%rsp)
  jne	.lerror
  cmpq	$0, -16(%rsp)
  jne	.lerror
  cmpq	$0, -24(%rsp)
  jne	.lerror
  cmpq	$0, -32(%rsp)
  jne	.lerror

  leaq	tst_entry, %rdi
  call	eri_tst_live_assert_thread_entry

  movl	$__NR_exit, %eax
  xorq	%rdi, %rdi
  syscall
  .size tst_start, . - tst_start

#define STUB(symbol) \
  ERI_GLOBAL_HIDDEN (symbol);					\
symbol:

  .align 16
  STUB (eri_live_syscall)
  STUB (eri_live_sync_async)
  STUB (eri_live_restart_sync_async)
  STUB (eri_live_atomic_hash_mem)
  STUB (eri_live_atomic_load)
  STUB (eri_live_atomic_stor)
  STUB (eri_live_atomic_load_stor)
.lerror:
  ERI_ASSERT_FALSE
