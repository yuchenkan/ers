#ifndef ERI_CONVERT_COMMON_H
#define ERI_CONVERT_COMMON_H

#include <stdint.h>
#include <stdio.h>

struct eri_seg;

/* segs freed by caller.  */
uint64_t eri_parse_elf (FILE *f, struct eri_seg **segs, uint16_t *nsegs);

#endif
