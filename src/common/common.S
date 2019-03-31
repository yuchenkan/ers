/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/syscall-offsets.h>

ERI_FUNCTION (sig_return_back)
  movq	%rbx, ERI_SIGFRAME_CTX_MCTX_RBX(%rdi)
  movq	%rsp, ERI_SIGFRAME_CTX_MCTX_RSP(%rdi)
  movq	%rbp, ERI_SIGFRAME_CTX_MCTX_RBP(%rdi)
  movq	%r12, ERI_SIGFRAME_CTX_MCTX_R12(%rdi)
  movq	%r13, ERI_SIGFRAME_CTX_MCTX_R13(%rdi)
  movq	%r14, ERI_SIGFRAME_CTX_MCTX_R14(%rdi)
  movq	%r15, ERI_SIGFRAME_CTX_MCTX_R15(%rdi)
  ERI_MOV_LM (.lsig_return_back, ERI_SIGFRAME_CTX_MCTX_RIP(%rdi), %rax)
  movq	%rdi, %rsp
.lsig_return_back:
  ret
  ERI_END_FUNCTION (sig_return_back)

ERI_FUNCTION (eri_sig_act)
  movq	%rdi, %rsp
  movq	%rsi, %rcx
  leaq	ERI_SIGFRAME_INFO(%rsp), %rsi
  movq	ERI_SIGINFO_SIG(%rsi), %rdi
  leaq	ERI_SIGFRAME_CTX(%rsp), %rdx
  xorq	%rax, %rax
  jmp	*%rcx
  ERI_END_FUNCTION (eri_sig_act)


