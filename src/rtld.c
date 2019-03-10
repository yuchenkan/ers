#include <rtld.h>

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/elf.h>

void
eri_map_bin (int32_t fd, struct eri_seg *segs, uint16_t nsegs,
	     uint64_t base, uint64_t page_size)
{
  uint16_t i;
  for (i = 0; i < nsegs; ++i)
    {
      uint64_t data_end = segs[i].vaddr + segs[i].filesz;
      uint64_t alloc_end = segs[i].vaddr + segs[i].memsz;

      uint64_t map_start = eri_round_down (segs[i].vaddr, page_size);
      uint64_t map_end = eri_round_up (data_end, page_size);

      uint64_t offset = eri_round_down (segs[i].offset, page_size);

      int32_t prot = segs[i].prot;

      eri_assert_syscall (mmap, base + map_start, map_end - map_start,
			  prot, ERI_MAP_FIXED | ERI_MAP_PRIVATE,
			  fd, offset);

      if (alloc_end > data_end)
	{
	  uint64_t zeroend = eri_round_up (alloc_end, page_size);
	  if (eri_round_down (data_end, page_size) != map_end)
	    {
	      if (! (prot & ERI_PROT_WRITE))
		eri_assert_syscall (mprotect, base + map_end - page_size,
				    page_size, prot | ERI_PROT_WRITE);

	      uint64_t c;
	      for (c = base + data_end; c < base + map_end; ++c)
		*(uint8_t *) c = 0;

	      if (! (prot & ERI_PROT_WRITE))
		eri_assert_syscall (mprotect, base + map_end - page_size,
				    page_size, prot);
	    }

	  if (zeroend > map_end)
	    eri_assert_syscall (mmap, base + map_end, zeroend - map_end,
		prot, ERI_MAP_FIXED | ERI_MAP_ANONYMOUS | ERI_MAP_PRIVATE,
		-1, 0);
	}
    }
}
