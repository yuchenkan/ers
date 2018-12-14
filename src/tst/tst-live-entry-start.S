/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

  .align 16
  ERI_GLOBAL_HIDDEN (tst_start)
  ERI_GLOBAL_HIDDEN (tst_exit)
  .type tst_start, @function
tst_start:
  pushq	$0x12345678
  pushq	$0x12345678
  movq	%rsp, %rdi
  movq	$0x12345678, %rsi
  leaq	tst_exit(%rip), %rdx
  pushq	$0x203
  orq	$ERI_TRACE_FLAG_MASK, (%rsp)
  jmp	tst_rtld
tst_exit:
  cmpb	$1, sigtrap_triggered
  jne	.lerror
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
