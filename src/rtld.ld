SECTIONS
{
  .text : { *(.text.start) *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  HIDDEN (eri_binary_end = .);
  /DISCARD/ : { *(.interp) }
}
