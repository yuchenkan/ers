#include <rtld.h>

#ifndef ERI_GENERATED_RECORDER_BINARY_H
# include <generated/recorder-binary.h>
#endif

#include <lib/util.c>
#include <lib/syscall.h>
#include <lib/printf.c>

void
rtld (void **args, uint64_t rdx, uint64_t rflags)
{
  extern uint8_t eri_binary_end[];
  struct eri_rtld_args rtld = {
    rdx, rflags, (uint64_t) args, (uint64_t) eri_binary_end
  };
  struct eri_sigset set;
  eri_sig_fill_set (&set);
  eri_assert_syscall (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      &rtld.sig_mask, ERI_SIG_SETSIZE);

  const char *rec = "recorder";
  uint64_t pagesz = 4096;

  uint64_t argc = *(uint64_t *) args;
  char **envp;
  for (envp = (char **) args + 1 + argc + 1; *envp; ++envp)
    if (eri_strncmp (*envp, "ERS_RECORDER=",
		     eri_strlen ("ERS_RECORDER=")) == 0)
      rec = *envp + eri_strlen ("ERS_RECORDER=");

  struct eri_auxv *auxv = (struct eri_auxv *) (envp + 1);
  struct eri_auxv *a;
  for (a = auxv; a->type != ERI_AT_NULL; ++a)
    if (a->type == ERI_AT_PAGESZ) pagesz = a->val;

  uint64_t fd = eri_assert_syscall (open, rec, ERI_O_RDONLY);

  struct eri_seg_args segs[] = ERI_RECORDER_BINARY_SEGMENTS;
  uint16_t nsegs = eri_length_of (segs);

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
	  base = eri_assert_syscall (
			mmap, mapstart, maplastend - mapstart + 2 * pagesz,
			0, ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0)
		 - mapstart + pagesz;
	  eri_assert_syscall (mmap, base + mapstart, mapend - mapstart,
			      prot, ERI_MAP_FIXED | ERI_MAP_PRIVATE,
			      fd, offset);

	  rtld.map_start = base + mapstart;
	  rtld.map_end = base + maplastend;
	}
      else
	eri_assert_syscall (mmap, base + mapstart, mapend - mapstart,
			    prot, ERI_MAP_FIXED | ERI_MAP_PRIVATE,
			    fd, offset);

      if (allocend > dataend)
	{
	  uint64_t zeroend = eri_round_up (allocend, pagesz);
	  if (eri_round_down (dataend, pagesz) != mapend)
	    {
	      if (! (prot & ERI_PROT_WRITE))
		eri_assert_syscall (mprotect, base + mapend - pagesz,
				    pagesz, prot | ERI_PROT_WRITE);

	      uint64_t c;
	      for (c = base + dataend; c < base + mapend; ++c)
		*(uint8_t *) c = 0;

	      if (! (prot & ERI_PROT_WRITE))
		eri_assert_syscall (mprotect, base + mapend - pagesz,
				    pagesz, prot);
	    }

	  if (zeroend > mapend)
	    eri_assert_syscall (mmap, base + mapend, zeroend - mapend,
		prot, ERI_MAP_FIXED | ERI_MAP_ANONYMOUS | ERI_MAP_PRIVATE,
		-1, 0);
	}
    }

  eri_assert_syscall (close, fd);

  ((void (*) (struct eri_rtld_args *)) (base + ERI_RECORDER_BINARY_ENTRY)) (&rtld);
}
