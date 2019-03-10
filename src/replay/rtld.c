#include <compiler.h>
#include <common.h>
#include <record.h>

#include <rtld.h>

#include <lib/util.h>
#include <lib/elf.h>
#include <lib/printf.h>

#include <replay/rtld.h>

struct init_map_args
{
  uint64_t size;
  uint64_t text_offset;

  int32_t fd;
  uint64_t page_size;

  uint64_t map_start;
  uint64_t map_end;
  uint64_t map_entry_offset;

  uint16_t nsegs;
  struct eri_seg segs[0];
};

eri_noreturn void eri_init_map (struct init_map_args *args);

eri_noreturn void
eri_init_map (struct init_map_args *args)
{
  uint64_t page_size = args->page_size;
  uint64_t size = eri_round_up (args->size, page_size);
  uint64_t start = (uint64_t) args;
  uint64_t end = start + size;
  uint64_t map_start = args->map_start;
  uint64_t map_end = args->map_end;

#define fixed_mmap(start, end) \
    eri_assert_syscall (mmap, start, end - start, 0, \
		ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, - 1, 0)
  uint8_t remap = end > map_start && start < map_end;
  if (! remap) fixed_mmap (map_start, map_end);
  else if (start <= map_start && end < map_end) fixed_mmap (end, map_end);
  else if (start > map_start && end >= map_end) fixed_mmap (map_start, start);
  else if (start > map_start && end < map_end)
    {
      fixed_mmap (map_start, start);
      fixed_mmap (end, map_end);
    }

  if (remap) /* XXX: regressively test remap */
    {
      uint64_t restart = eri_assert_syscall (mmap, 0, size,
			ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
      eri_memcpy ((void *) restart, (void *) start, args->size);

      uint64_t text = restart + args->text_offset;
      ((void (*) (struct init_map_args *)) text) ((void *) restart);
      eri_assert_unreachable ();
    }

  int32_t fd = args->fd;
  struct eri_elf64_ehdr ehdr;
  eri_assert_sys_read (fd, &ehdr, sizeof ehdr);
  eri_assert_elf (ehdr.ident);
  uint64_t entry = ehdr.entry + args->map_entry_offset;

  struct eri_seg *segs = args->segs;
  uint16_t nsegs = args->nsegs;
  eri_map_bin (fd, segs, nsegs, map_start, page_size);
  eri_assert_syscall (close, fd);

  const char *path = (void *) (segs + nsegs);

  uint64_t segs_map_start = eri_round_down (segs[0].vaddr, page_size);
  uint64_t segs_alloc_end = segs[nsegs - 1].vaddr + segs[nsegs - 1].memsz;
  uint64_t segs_map_end = eri_round_up (segs_alloc_end, page_size);
  uint64_t segs_map_size = segs_map_end - segs_map_start;
  eri_assert (segs_map_size <= map_end - map_start);
  struct eri_replay_rtld_args rtld_args = {
    path, map_start + segs_map_size, map_end - map_start - segs_map_size
  };
  ((void (*) (struct eri_replay_rtld_args *)) entry) (&rtld_args);
  eri_assert_unreachable ();
}

/* TODO */
eri_noreturn void eri_replay_start (struct eri_replay_rtld_args *args);

eri_noreturn void rtld (void **args);

eri_noreturn void
rtld (void **args)
{
  char *path = "ers-data";
  char **envp;
  for (envp = eri_get_envp_from_args (args); *envp; ++envp)
    eri_get_arg_str (*envp, "ERS_DATA=", &path);

  struct eri_elf64_phdr *phdrs = 0;
  uint64_t phnum = 0;
  uint64_t page_size = 4096; /* XXX: check page_size */

  struct eri_auxv *auxv;
  for (auxv = (struct eri_auxv *)(envp + 1);
       auxv->type != ERI_AT_NULL; ++auxv)
    if (auxv->type == ERI_AT_PHDR) phdrs = auxv->ptr;
    else if (auxv->type == ERI_AT_PHENT)
      eri_assert (auxv->val == sizeof (struct eri_elf64_phdr));
    else if (auxv->type == ERI_AT_PHNUM) phnum = auxv->val;
    else if (auxv->type == ERI_AT_PAGESZ) page_size = auxv->val;

  eri_assert (phdrs && phnum);

  uint16_t i, nsegs = 0;
  for (i = 0; i < phnum; ++i)
    if (phdrs[i].type == ERI_PT_LOAD) ++nsegs;

  eri_assert (nsegs);
  struct eri_seg segs[nsegs];
  uint16_t j = 0;
  for (i = 0; i < phnum; ++i)
    if (phdrs[i].type == ERI_PT_LOAD)
      eri_seg_from_phdr (segs + j++, phdrs + i);

/* TODO */
#if 0
  char name[eri_build_path_len (path, "t", 0)];
  eri_build_path (path, "t", 0, name);

  eri_file_t file;
  eri_assert_fopen (name, 1, &file, 0, 0);

  struct eri_init_record init;
  eri_assert_fread (file, &init, sizeof init, 0);
  eri_assert_fclose (file);
#endif

  struct init_map_args init_args = {
    .fd = eri_assert_syscall (open, "/proc/self/exe", ERI_O_RDONLY),
    .page_size = page_size,
#if 0
    .map_start = init.start, .map_end = init.end,
#else
    .map_start = 1024 * 1024 * 1024, .map_end = 1088 * 1024 * 1024,
#endif
    .map_entry_offset
	= (uint64_t) eri_replay_start - (uint64_t) eri_start,
    .nsegs = nsegs
  };
  uint64_t data_size = sizeof init_args + sizeof segs + eri_strlen (path) + 1;
  init_args.text_offset = eri_round_up (data_size, 16);

  extern uint8_t eri_init_map_text_start[];
  extern uint8_t eri_init_map_text_end[];
  uint64_t text_size = eri_init_map_text_end - eri_init_map_text_start;
  init_args.size = init_args.text_offset + text_size;

  struct init_map_args *a = (void *) eri_assert_syscall (mmap, 0,
			eri_round_up (init_args.size, page_size),
			ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  eri_memcpy (a, &init_args, sizeof *a);
  eri_memcpy (a->segs, segs, sizeof segs);
  eri_strcpy ((void *) (a->segs + nsegs), path);
  uint64_t text = (uint64_t) a + a->text_offset;
  //eri_assert_printf ("%lx %lx\n", text, eri_init_map_text_start);
  eri_memcpy ((void *) text, eri_init_map_text_start, text_size);

  ((void (*) (struct init_map_args *)) text) (a);
  eri_assert_unreachable ();
}
