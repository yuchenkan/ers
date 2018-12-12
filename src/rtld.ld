SECTIONS
{
  .text : { *(.text.start) *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  HIDDEN (binary_end = .);
  /DISCARD/ : { *(.interp) }
}
