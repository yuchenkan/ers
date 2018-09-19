asm ("  .text			\n\
  .align 16			\n\
  .global _start		\n\
_start:				\n\
  xorq	%rdi, %rdi		\n\
  xorq	%rsi, %rsi		\n\
  xorq	%rdx, %rdx		\n\
  call	entry			\n\
  .size _start, .-_start	\n\
  .previous			\n"
);
