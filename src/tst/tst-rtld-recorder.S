  .text

  .align 16
  .global tst_start
  .hidden tst_start
  .type tst_start, @function
tst_start:
  pushq	%rdi
  call	tst_rtld
  popq	%rdi
  movq	(%rdi), %rsp
  jmp	*8(%rdi)
  .size tst_start, . - tst_start
