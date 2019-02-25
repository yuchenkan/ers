SECTIONS
{
  . = ALIGN (_end, CONSTANT (MAXPAGESIZE));
  HIDDEN (tst_live_map_start = .);
  .text.live		: { tst/tst-live.a:live.l(.text .text.unlikely) }
  .rodata.live		: { tst/tst-live.a:live.l(.rodata .rodata.*) }
  .eh_frame.live	: ONLY_IF_RO { KEEP (tst/tst-live.a:live.l(.eh_frame)) }
  . = ALIGN (CONSTANT (MAXPAGESIZE));
  .eh_frame.live	: ONLY_IF_RW { KEEP (tst/tst-live.a:live.l(.eh_frame)) }
  .data.live		: { tst/tst-live.a:live.l(.data) }
  .bss.live		: { tst/tst-live.a:live.l(.bss) }
  . = ALIGN (8);
  HIDDEN (tst_live_map_end = .);
}

INSERT AFTER /DISCARD/
