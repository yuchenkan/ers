/* vim: set ft=gas: */

#include <lib/util.h>

  .text

#ifndef TST_INIT
# define TST_INIT
#endif

#ifndef TST_MAIN
# define TST_MAIN tst_main
#endif

ERI_FUNCTION (tst_start)
  TST_INIT
  movq	%rdi, %rsi	/* ERI_TST_DIVERGE */
  movq	%rsp, %rdi
  call	TST_MAIN
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (tst_start)
