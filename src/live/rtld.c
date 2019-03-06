#include <lib/elf.h>
#include <lib/util.c>
#include <lib/syscall.h>
#include <lib/syscall.c>
#include <lib/printf.c>

#include <live/rtld.h>

void
rtld (void **args, uint64_t rdx, uint64_t rflags)
{
  extern uint8_t eri_binary_end[];
  struct eri_live_rtld_args rtld_args = {
    rdx, rflags, (uint64_t) args, (uint64_t) eri_binary_end
  };
  struct eri_sigset set;
  eri_sig_fill_set (&set);
  eri_assert_syscall (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      &rtld_args.sig_mask, ERI_SIG_SETSIZE);

  const char *rec = "ers/live";
  uint64_t buf_size = 256 * 1024 * 1024;
  uint64_t page_size = 4096;

  uint64_t argc = *(uint64_t *) args;
  char **envp;
  for (envp = (char **) args + 1 + argc + 1; *envp; ++envp)
    if (eri_strncmp (*envp, "ERS_LIVE=",
		     eri_strlen ("ERS_LIVE=")) == 0)
      rec = *envp + eri_strlen ("ERS_LIVE=");
  /* XXX: parameterize */
  rtld_args.buf_size = buf_size;

  struct eri_auxv *auxv = (struct eri_auxv *) (envp + 1);
  struct eri_auxv *a;
  for (a = auxv; a->type != ERI_AT_NULL; ++a)
    if (a->type == ERI_AT_PAGESZ) page_size = a->val;
  rtld_args.page_size = page_size;

  uint64_t fd = eri_assert_syscall (open, rec, ERI_O_RDONLY);

  uint8_t buf[sizeof (uint64_t) + sizeof (uint16_t)];
  eri_assert_syscall (lseek, fd, -sizeof buf, ERI_SEEK_END);
  eri_assert_sys_read (fd, buf, sizeof buf);
  uint16_t nsegs = *(uint16_t *) buf;
  uint64_t entry = *(uint64_t *) (buf + sizeof nsegs);

  struct eri_seg segs[nsegs];
  eri_assert_syscall (lseek, fd, -(sizeof segs + sizeof buf), ERI_SEEK_END);
  eri_assert_sys_read (fd, segs, sizeof segs);

  uint64_t base = 0;
  uint16_t i;
  for (i = 0; i < nsegs; ++i)
    {
      uint64_t data_end = segs[i].vaddr + segs[i].filesz;
      uint64_t alloc_end = segs[i].vaddr + segs[i].memsz;

      uint64_t map_start = eri_round_down (segs[i].vaddr, page_size);
      uint64_t map_end = eri_round_up (data_end, page_size);

      uint64_t offset = eri_round_down (segs[i].offset, page_size);

      int32_t prot = segs[i].prot;
      if (i == 0)
	{
	  uint64_t alloc_last_end = segs[nsegs - 1].vaddr
					+ segs[nsegs - 1].memsz;
	  uint64_t map_last_end = eri_round_up (alloc_last_end, page_size);
	  base = eri_assert_syscall (mmap, map_start - page_size,
			map_last_end - map_start + buf_size + 3 * page_size,
			0, ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0)
			+ page_size - map_start;

	  eri_assert_syscall (mmap, base + map_start, map_end - map_start,
			      prot, ERI_MAP_FIXED | ERI_MAP_PRIVATE,
			      fd, offset);

	  rtld_args.map_start = base + map_start - page_size;
	  rtld_args.buf = base + map_last_end + page_size;
	  rtld_args.map_end =  rtld_args.buf + buf_size + page_size;
	}
      else
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

  eri_assert_syscall (close, fd);

  ((void (*) (void *)) (base + entry)) (&rtld_args);
}
