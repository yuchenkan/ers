#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/elf.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#include <common/debug.h>
#include <common/rtld.h>
#include <common/common.h>
#include <common/serial.h>

#include <replay/rtld.h>
#include <replay/thread.h>

#define INIT_STACK_SIZE		(1024 * 4096)

struct init_map_args
{
  uint64_t init_size;
  uint64_t size;
  uint64_t text_offset;

  uint64_t debug;

  uint8_t conf;
  uint8_t log;

  int32_t fd;
  uint64_t page_size;

  uint64_t stack_size;
  uint64_t file_buf_size;

  uint64_t diverge;

  uint64_t map_start;
  uint64_t map_end;
  uint64_t map_entry_offset;

  uint16_t nsegs;
  struct eri_seg segs[0];
};

eri_noreturn void init_map (uint64_t stack, struct init_map_args *args);

#define call_init_map(a) \
  do {									\
    struct init_map_args *_a = a;					\
    ((typeof (&init_map)) ((uint64_t) _a + _a->text_offset)) (		\
					(uint64_t) _a + _a->size, _a);	\
  } while (0)

eri_noreturn void
eri_init_map (struct init_map_args *args)
{
  uint64_t page_size = args->page_size;
  uint64_t size = args->size;
  uint64_t start = (uint64_t) args;
  uint64_t end = start + size;
  uint64_t map_start = args->map_start;
  uint64_t map_end = args->map_end;

#define fixed_mmap(start, end) \
    eri_assert_syscall (mmap, start, end - start, 0, \
		ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0)
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
      uint64_t i;
      for (i = 0; i < args->init_size; ++i)
	((uint8_t *) restart)[i] = ((uint8_t *) start)[i];

      call_init_map ((void *) restart);
    }

  /* NOTE: most utils not work in this function.  */

  int32_t fd = args->fd;
  struct eri_elf64_ehdr ehdr;
  eri_assert_sys_read (fd, &ehdr, sizeof ehdr);
  eri_assert_elf (ehdr.ident);
  uint64_t entry = ehdr.entry + args->map_entry_offset;

  struct eri_seg *segs = args->segs;
  uint16_t nsegs = args->nsegs;
  /* Work as guard page for writes.  */
  eri_assert (! (segs[0].prot & ERI_PROT_WRITE));
  eri_map_bin (fd, segs, nsegs, map_start, page_size);

  eri_assert (ehdr.shentsize == sizeof (struct eri_elf64_shdr));
  eri_assert (ehdr.shnum < 128);

  struct eri_elf64_shdr shdrs[ehdr.shnum];
  eri_assert_syscall (lseek, fd, ehdr.shoff, ERI_SEEK_SET);
  eri_assert_sys_read (fd, shdrs, sizeof shdrs);

  uint64_t i, j, k;
  for (i = 0; i < ehdr.shnum; ++i)
    if (shdrs[i].type == ERI_SHT_RELA)
      {
	uint64_t nrels = shdrs[i].size / sizeof (struct eri_elf64_rela);
	struct eri_elf64_rela relas[1024];
	struct eri_relative rels[eri_length_of (relas)];
	eri_assert_syscall (lseek, fd, shdrs[i].offset, ERI_SEEK_SET);

	for (j = 0; j < nrels; j += eri_length_of (relas))
	  {
	    uint64_t n = eri_min (eri_length_of (relas), nrels - j);
	    eri_assert_sys_read (fd, relas, sizeof relas[0] * n);
	    for (k = 0; k < n; ++k)
	      {
		eri_assert (eri_elf64_r_type (relas[k].info)
						  == R_X86_64_RELATIVE);
		rels[k].offset = relas[k].offset;
		rels[k].addend = relas[k].addend;
	      }
	    eri_map_reloc (rels, n, map_start);
	  }
	break;
      }

  eri_assert_syscall (close, fd);

  const char *c = (void *) (segs + nsegs);
  const char *path = c;
  while (*c++) continue;
  const char *conf = args->conf ? c : 0;
  if (args->conf) while (*c++) continue;
  const char *log = args->log ? c : 0;

  uint64_t segs_map_start = eri_round_down (segs[0].vaddr, page_size);
  uint64_t segs_alloc_end = segs[nsegs - 1].vaddr + segs[nsegs - 1].memsz;
  uint64_t segs_map_end = eri_round_up (segs_alloc_end, page_size);
  uint64_t segs_map_size = segs_map_end - segs_map_start;
  eri_assert (segs_map_size <= map_end - map_start);
  struct eri_replay_rtld_args rtld_args = {
    { map_start, map_end }, page_size, args->debug, path, conf, log,
    args->stack_size, args->file_buf_size, args->diverge,
    map_start + segs_map_end, map_end - map_start - segs_map_end
  };
  ((void (*) (void *)) map_start + entry) (&rtld_args);
  eri_assert_unreachable ();
}

eri_noreturn void
rtld (void **args)
{
  struct eri_sigset set;
  eri_sig_fill_set (&set);
  eri_assert_sys_sigprocmask (&set, 0);

  const char *path = "ers-data";
  const char *conf = 0;
  const char *log = 0;
  uint64_t stack_size = 2 * 1024 * 1024;
  uint64_t file_buf_size = 64 * 1024;
  uint64_t diverge = 0;
  char **envp;
  for (envp = eri_get_envp_from_args (args); *envp; ++envp)
    (void) (eri_get_arg_str (*envp, "ERS_DATA=", (void *) &path)
    || eri_get_arg_str (*envp, "ERS_CONF=", (void *) &conf)
    || eri_get_arg_int (*envp, "ERS_STACK_SIZE=", &stack_size, 10)
    || eri_get_arg_int (*envp, "ERS_FILE_BUF_SIZE=", &file_buf_size, 10)
    || eri_get_arg_str (*envp, "ERI_LOG=", (void *) &log)
    || eri_get_arg_int (*envp, "ERI_DIVERGE=", &diverge, 10)
    || eri_get_arg_int (*envp, "ERI_DEBUG=", &eri_global_enable_debug, 10));

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

  char name[eri_build_path_len (path, "t", 0)];
  eri_build_path (path, "t", 0, name);

  eri_file_t file;
  if (eri_fopen (name, 1, &file, 0, 0))
    {
      eri_assert_fprintf (ERI_STDERR, "failed to open data: %s\n", name);
      eri_assert_syscall (exit, 1);
    }

  eri_assert (eri_unserialize_mark (file) == ERI_INIT_RECORD);
  struct eri_init_record rec;
  eri_unserialize_init_record (file, &rec);

  struct init_map_args init_args = {
    .debug = eri_global_enable_debug,
    .conf = !! conf, .log = !! log,
    .fd = eri_assert_syscall (open, "/proc/self/exe", ERI_O_RDONLY),
    .page_size = page_size,
    .stack_size = stack_size, .file_buf_size = file_buf_size,
    .diverge = diverge,
    .map_start = rec.map_range.start, .map_end = rec.map_range.end,
    .map_entry_offset
	/* main replay entry: eri_replay_start */
	= (uint64_t) eri_replay_start - (uint64_t) eri_start,
    .nsegs = nsegs
  };
  uint64_t data_size = sizeof init_args + sizeof segs
	+ eri_strlen (path) + 1 + (conf ? eri_strlen (conf) + 1 : 0)
	+ (log ? eri_strlen (log) + 1 : 0);
  uint64_t text_start_offset = eri_round_up (data_size, 16);

  extern uint8_t eri_init_map_text_start[];
  extern uint8_t eri_init_map_text_end[];
  uint64_t text_size = eri_init_map_text_end - eri_init_map_text_start;
  init_args.init_size = text_start_offset + text_size;
  init_args.size
	= eri_round_up (init_args.init_size + INIT_STACK_SIZE, page_size);
  init_args.text_offset
	= text_start_offset + (uint8_t *) init_map - eri_init_map_text_start;

  struct init_map_args *a = (void *) eri_assert_syscall (mmap, 0,
		init_args.size, ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  eri_memcpy (a, &init_args, sizeof *a);
  eri_memcpy (a->segs, segs, sizeof segs);

  char *c = (void *) (a->segs + nsegs);
  eri_strcpy (c, path);
  c += eri_strlen (path) + 1;
  if (conf)
    {
      eri_strcpy (c, conf);
      c += eri_strlen (conf) + 1;
    }
  if (log) eri_strcpy (c, log);

  uint64_t text_start = (uint64_t) a + text_start_offset;
  //eri_assert_printf ("%lx %lx\n", text, eri_init_map_text_start);
  eri_memcpy ((void *) text_start, eri_init_map_text_start, text_size);

  //a->map_start = (uint64_t) a;
  //a->map_end = a->map_start + 64 * 1024 * 1024;
  eri_debug ("\n");
  call_init_map (a);
}
