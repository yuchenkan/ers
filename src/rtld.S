/* vim: set ft=gas: */

  .section .text.start, "ax", @progbits

  .align 16
  .global eri_start
  .hidden eri_start
  .type eri_start, @function
eri_start:
  movq	%rsp, %rdi
  pushq	$0
  jmp	eri_rtld
  .size eri_start, . - eri_start
