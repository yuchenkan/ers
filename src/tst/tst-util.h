#ifndef TST_TST_TST_UTIL_H
#define TST_TST_TST_UTIL_H

#include <stdint.h>

#include <lib/compiler.h>

static eri_unused uint32_t
tst_bswap32 (uint32_t x)
{
  return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8)
	 | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
}

#endif
