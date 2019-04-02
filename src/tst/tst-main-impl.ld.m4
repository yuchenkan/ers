/* vim: set ft=ld: */
SECTIONS
{
  . = ALIGN (_end, CONSTANT (MAXPAGESIZE));
  HIDDEN (tst_main_map_start = .);
  .text.main.map	: { m4_main(.text .text.unlikely) }
  .rodata.main.map	: { m4_main(.rodata .rodata.*) }
  .eh_frame.main.map	: ONLY_IF_RO { KEEP (m4_main(.eh_frame)) }
  . = ALIGN (CONSTANT (MAXPAGESIZE));
  .eh_frame.main.map	: ONLY_IF_RW { KEEP (m4_main(.eh_frame)) }
  .data.main.map	: { m4_main(.data) }
  .bss.main.map		: { m4_main(.bss) }
  . = ALIGN (CONSTANT (MAXPAGESIZE));
  HIDDEN (tst_main_buf_start = .);
  . = . + 256 * 1024 * 1024;
  . = ALIGN (CONSTANT (MAXPAGESIZE));
  HIDDEN (tst_main_buf_end = .);
  HIDDEN (tst_main_map_end = .);
}

INSERT AFTER /DISCARD/
