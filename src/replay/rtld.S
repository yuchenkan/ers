/* vim: set ft=gas: */

#include <lib/util.h>

  .text

ERI_FUNCTION (eri_start)
  movq	%rsp, %rdi
  jmp	rtld
  ERI_END_FUNCTION (eri_start)

  .section .text.eri_init_map, "ax", @progbits

ERI_FUNCTION (init_map)
  movq	%rdi, %rsp
  movq	%rsi, %rdi
  call	eri_init_map
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (init_map)
