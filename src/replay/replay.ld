SECTIONS
{
  . = ALIGN (16);
  HIDDEN (eri_init_map_text_start = .);
  .text.init_map	: { *(.text.eri_init_map) *(.text.eri_map_bin)  *(.text.eri_map_reloc) }
  HIDDEN (eri_init_map_text_end = .);
}

INSERT BEFORE .text
