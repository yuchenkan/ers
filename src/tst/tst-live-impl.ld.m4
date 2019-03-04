/* vim: set ft=ld: */
SECTIONS
{
  . = ALIGN (_end, CONSTANT (MAXPAGESIZE));
  HIDDEN (tst_live_map_start = .);
  .text.live		: { m4_live(.text .text.unlikely) }
  .rodata.live		: { m4_live(.rodata .rodata.*) }
  .eh_frame.live	: ONLY_IF_RO { KEEP (m4_live(.eh_frame)) }
  . = ALIGN (CONSTANT (MAXPAGESIZE));
  .eh_frame.live	: ONLY_IF_RW { KEEP (m4_live(.eh_frame)) }
  .data.live		: { m4_live(.data) }
  .bss.live		: { m4_live(.bss) }
  . = ALIGN (CONSTANT (MAXPAGESIZE));
  HIDDEN (tst_live_buf_start = .);
  . = . + 256 * 1024 * 1024;
  . = ALIGN (CONSTANT (MAXPAGESIZE));
  HIDDEN (tst_live_buf_end = .);
  HIDDEN (tst_live_map_end = .);
}

INSERT AFTER /DISCARD/
