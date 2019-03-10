/* vim: set ft=gas: */

#include <lib/util.h>

ERI_FUNCTION (eri_start)
  movq	%rsp, %rdi
  jmp	rtld
  ERI_END_FUNCTION (eri_start)
