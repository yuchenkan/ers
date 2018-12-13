#include <stdint.h>

#include "rtld.h"
#ifndef ERI_TST_RTLD
# include "recorder-binary.h"
#else
# include "tst-rtld-recorder-binary.h"
#endif

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/printf.h"

void
eri_rtld (void **arg)
{
#ifdef ERI_TST_RTLD
  arg += 2;
  const char *rec = "tst-rtld-recorder";
#else
  const char *rec = "recorder";
#endif
  uint64_t pagesz = 4096;

  uint64_t argc = *(uint64_t *) arg;
  char **envp;
  for (envp = (char **) arg + 1 + argc + 1; *envp; ++envp)
    if (eri_strncmp (*envp, "ERS_RECORDER=",
		     eri_strlen ("ERS_RECORDER=")) == 0)
      rec = *envp + eri_strlen ("ERS_RECORDER=");

  struct eri_auxv *auxv = (struct eri_auxv *) (envp + 1);
  struct eri_auxv *a;
  for (a = auxv; a->type != ERI_AT_NULL; ++a)
    if (a->type == ERI_AT_PAGESZ) pagesz = a->val;

  uint64_t fd = ERI_ASSERT_SYSCALL_RES (open, rec, ERI_O_RDONLY);

  struct eri_seg segs[] = ERI_RECORDER_BINARY_SEGMENTS;
  uint16_t nsegs = eri_length_of (segs);

  extern uint8_t eri_binary_end[];
  struct eri_rtld r = { (uint64_t) arg, (uint64_t) eri_binary_end };

  uint64_t base;
  uint16_t i;
  for (i = 0; i < nsegs; ++i)
    {
      uint64_t dataend = segs[i].vaddr + segs[i].filesz;
      uint64_t allocend = segs[i].vaddr + segs[i].memsz;

      uint64_t mapstart = eri_round_down (segs[i].vaddr, pagesz);
      uint64_t mapend = eri_round_up (dataend, pagesz);

      uint64_t offset = eri_round_down (segs[i].offset, pagesz);

      int32_t prot = segs[i].prot;
      if (i == 0)
	{
	  uint64_t alloclastend = segs[nsegs - 1].vaddr
				  + segs[nsegs - 1].memsz;
	  uint64_t maplastend = eri_round_up (alloclastend, pagesz);
	  base = ERI_ASSERT_SYSCALL_RES (
			mmap, mapstart, maplastend - mapstart + 2 * pagesz,
			0, ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0)
		 - mapstart + pagesz;
	  ERI_ASSERT_SYSCALL (mmap, base + mapstart, mapend - mapstart,
			      prot, ERI_MAP_FIXED | ERI_MAP_PRIVATE,
			      fd, offset);

	  r.map_start = base + mapstart;
	  r.map_end = base + maplastend;
	}
      else
	ERI_ASSERT_SYSCALL (mmap, base + mapstart, mapend - mapstart,
			    prot, ERI_MAP_FIXED | ERI_MAP_PRIVATE,
			    fd, offset);

      if (allocend > dataend)
	{
	  uint64_t zeroend = eri_round_up (allocend, pagesz);
	  if (eri_round_down (dataend, pagesz) != mapend)
	    {
	      if (! (prot & ERI_PROT_WRITE))
		ERI_ASSERT_SYSCALL (mprotect, base + mapend - pagesz,
				    pagesz, prot | ERI_PROT_WRITE);

	      uint64_t c;
	      for (c = base + dataend; c < base + mapend; ++c)
		*(uint8_t *) c = 0;

	      if (! (prot & ERI_PROT_WRITE))
		ERI_ASSERT_SYSCALL (mprotect, base + mapend - pagesz,
				    pagesz, prot);
	    }

	  if (zeroend > mapend)
	    ERI_ASSERT_SYSCALL (mmap, base + mapend, zeroend - mapend,
		prot, ERI_MAP_FIXED | ERI_MAP_ANONYMOUS | ERI_MAP_PRIVATE,
		-1, 0);
	}
    }

  ERI_ASSERT_SYSCALL (close, fd);

  ((void (*) (struct eri_rtld *)) (base + ERI_RECORDER_BINARY_ENTRY)) (&r);
}
