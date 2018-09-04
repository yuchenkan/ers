#include <stdint.h>

#include "recorder.h"
#include "common.h"
#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/printf.h"

static struct ers_info info;

asm ("  .text			\n\
  .align 16			\n\
  .global entry			\n\
entry:				\n\
  testq	%rsi, %rsi		\n\
  jz	1f			\n\
  movq	$0, %r15		\n\
  movq	$0, (%r15)		\n\
1:				\n\
  movq	%rsp, %rdi		\n\
  call	start			\n\
  leaq	info(%rip), %rsi	\n\
  jmp	*%rax			\n\
  .size entry, .-entry		\n\
  .previous			\n"
);

struct elf64_rela
{
  uint64_t offset;
  uint64_t info;
  int32_t addend;
};

struct elf64_sym
{
  uint32_t name;
  unsigned char info;
  unsigned char other;
  uint16_t shndx;
  uint64_t value;
  uint64_t size;
};

#define STT_GNU_IFUNC	10

#define R_X86_64_NONE		0
#define R_X86_64_JUMP_SLOT	7
#define R_X86_64_RELATIVE	8

static void
relocate (uint64_t base, const struct elf64_rela *rel, const struct elf64_rela *rel_end,
	  const struct elf64_sym *symtab, const char *strtab)
{
  const struct elf64_rela *r;
  for (r = rel; r < rel_end; ++r)
  {
    const struct elf64_sym *sym = symtab + (r->info >> 32);
    uint32_t type = r->info & 0xffffffff;

    eri_assert (eri_printf ("rel sym %lu %lu %s %u\n",
			    r->info >> 32, sym->name, strtab + sym->name, type) == 0);

    eri_assert ((sym->info & 0xf) != STT_GNU_IFUNC);
    if (type == R_X86_64_NONE)
      continue;
    else if (type == R_X86_64_RELATIVE)
      *(uint64_t *) (r->offset + base) = base + r->addend;
    else if (type == R_X86_64_JUMP_SLOT)
      *(uint64_t *) (r->offset + base) = base + sym->value + r->addend;
    else
      eri_assert (0);
  }
}

#define EI_NIDENT	16

struct elf64_ehdr
{
  unsigned char ident[EI_NIDENT];
  uint16_t type;
  uint16_t machine;
  uint32_t version;
  uint64_t entry;
  uint64_t phoff;
  uint64_t shoff;
  uint32_t flags;
  uint16_t ehsize;
  uint16_t phentsize;
  uint16_t phnum;
  uint16_t shentsize;
  uint16_t shnum;
  uint16_t shstrndx;
};

struct elf64_phdr
{
  uint32_t type;
  uint32_t flags;
  uint64_t offset;
  uint64_t vaddr;
  uint64_t paddr;
  uint64_t filesz;
  uint64_t memsz;
  uint64_t align;
};

#define PF_X	0x1
#define PF_W	0x2
#define PF_R	0x4

#define PT_LOAD		1

static uint64_t
map_interp (struct elf64_phdr *phdr, uint16_t phnum, int fd, uint64_t pagesize)
{
  uint16_t i;

  uint64_t start = 0;
  uint64_t end = 0;
  uint16_t last_idx = 0;
  for (i = 0; i < phnum; ++i)
    if (phdr[i].type == PT_LOAD)
      {
	if (!start) start = phdr[i].vaddr;
	end = phdr[i].vaddr + phdr[i].memsz;
	last_idx = i;
      }

  eri_assert (eri_printf ("start %lx end %lx\n", start, end) == 0);

  uint64_t base = 0;
  for (i = 0; i < phnum; ++i)
    if (phdr[i].type == PT_LOAD)
      {
	uint64_t dataend = base + phdr[i].vaddr + phdr[i].filesz;
	uint64_t allocend = base + phdr[i].vaddr + phdr[i].memsz;

	uint64_t mapstart = eri_round_down (base + phdr[i].vaddr, pagesize);
	uint64_t mapend = eri_round_up (dataend, pagesize);
	uint64_t offset = eri_round_down (phdr[i].offset, pagesize);

	int prot = 0;
	if (phdr[i].flags & PF_R) prot |= ERI_PROT_READ;
	if (phdr[i].flags & PF_W) prot |= ERI_PROT_WRITE;
	if (phdr[i].flags & PF_X) prot |= ERI_PROT_EXEC;

	if (i == 0)
	  {
	    uint64_t maxend = phdr[last_idx].vaddr + phdr[last_idx].memsz;
	    uint64_t mapmaxend = eri_round_up (maxend, pagesize);
	    base = ERI_ASSERT_SYSCALL_RES (mmap, mapstart, mapmaxend - mapstart,
					   prot, ERI_MAP_COPY | ERI_MAP_FILE,
					   fd, offset) - mapstart;
	    ERI_ASSERT_SYSCALL (mprotect, base + mapend, mapmaxend - mapend, 0);
	  }
	else
	  ERI_ASSERT_SYSCALL (mmap, mapstart, mapend - mapstart,
			      prot, ERI_MAP_FIXED | ERI_MAP_COPY | ERI_MAP_FILE,
			      fd, offset);

	if (allocend > dataend)
	  {
	    uint64_t zeroend = eri_round_up (allocend, pagesize);
	    if (eri_round_down (dataend, pagesize) != mapend)
	      {
		if (! (prot & ERI_PROT_WRITE))
		  ERI_ASSERT_SYSCALL (mprotect, eri_round_down (dataend, pagesize),
				      pagesize, prot | ERI_PROT_WRITE);

		uint64_t c;
		for (c = dataend; c < mapend; ++c)
		  *(char *) c = '\0';

		if (! (prot & ERI_PROT_WRITE))
		  ERI_ASSERT_SYSCALL (mprotect, eri_round_down (dataend, pagesize),
				      pagesize, prot);
	      }
	    if (zeroend > mapend)
	      ERI_ASSERT_SYSCALL (mmap, mapend, zeroend - mapend,
				  prot,
				  ERI_MAP_ANONYMOUS | ERI_MAP_PRIVATE | ERI_MAP_FIXED,
				  -1, 0);
	  }
      }

  eri_assert (eri_printf ("base %lx\n", base) == 0);
  return base;
}


#define ELFMAG "\177ELF"
#define assert_elf(ident) \
  eri_assert ((ident)[0] == *(char *) ELFMAG		\
	      && (ident)[1] == *((char *) ELFMAG + 1)	\
	      && (ident)[2] == *((char *) ELFMAG + 2)	\
	      && (ident)[3] == *((char *) ELFMAG + 3));

static uint64_t
load_interp (const char *interp, uint64_t *entry, uint64_t pagesize)
{
  int fd;
  eri_assert (eri_fopen (interp, 1, &fd) == 0);

  struct elf64_ehdr ehdr;
  eri_assert (eri_fread (fd, (char *) &ehdr, sizeof ehdr, 0) == 0);

  assert_elf (ehdr.ident);
  eri_assert (ehdr.phentsize == sizeof (struct elf64_phdr));

  size_t sz = ehdr.phentsize * ehdr.phnum;
  struct elf64_phdr *phdr = __builtin_alloca (sz);

  eri_assert (eri_fseek (fd, ehdr.phoff, 0) == 0);
  eri_assert (eri_fread (fd, (char *) phdr, sz, 0) == 0);

  uint64_t base = map_interp (phdr, ehdr.phnum, fd, pagesize);

  *entry = base + ehdr.entry;

  eri_assert (eri_fclose (fd) == 0);
  return base;
}

struct elf64_auxv
{
  uint64_t type;
  uint64_t val;
};

struct elf64_dyn
{
  uint64_t tag;
  uint64_t val;
};

#define AT_NULL		0
#define AT_EXECFD	2
#define AT_PHDR		3
#define AT_PHENT	4
#define AT_PHNUM	5
#define AT_PAGESZ	6
#define AT_BASE		7

#define DT_NULL		0
#define DT_PLTRELSZ	2
#define DT_STRTAB	5
#define DT_SYMTAB	6
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_PLTREL	20
#define DT_JMPREL	23

/* XXX */
#define DEFAULT_ORIGINAL_INTERPRETER "/work/glibc-obj/elf/ld.so"

struct ers_recorder *eri_get_recorder (void);

static uint64_t __attribute__ ((used))
start (void **arg)
{
  struct ers_info *ip = &info;

  char disable = 0;
  uint64_t argc = *(uint64_t *) arg;
  char **envp;
  ip->libname = DEFAULT_ORIGINAL_INTERPRETER;
  for (envp = (char **) arg + 1 + argc + 1; *envp; ++envp)
    if (eri_strncmp (*envp, "ERS_ORIGINAL_INTERPRETER=",
		     eri_strlen ("ERS_ORIGINAL_INTERPRETER=")) == 0)
      ip->libname = *envp + eri_strlen ("ERS_ORIGINAL_INTERPRETER=");
    else if (eri_strncmp (*envp, "ERS_DISABLE_RECORD=",
			  eri_strlen ("ERS_DISABLE_RECORD=")) == 0)
      disable = eri_strcmp (*envp + eri_strlen ("ERS_DISABLE_RECORD="), "1") == 0;

  uint64_t base = 0;
  uint64_t *basep = 0;

  struct elf64_phdr *phdr = 0;
  uint64_t phnum = 0;

  uint64_t pagesize = 4096;

  struct elf64_auxv *auxv = (struct elf64_auxv *) (envp + 1);
  struct elf64_auxv *a;
  for (a = auxv; a->type != AT_NULL; ++a)
    if (a->type == AT_BASE)
      {
	base = a->val;
	basep = &a->val;
      }
    else if (a->type == AT_EXECFD)
      eri_assert (0);
    else if (a->type == AT_PHDR)
      phdr = (struct elf64_phdr *) a->val;
    else if (a->type == AT_PHENT)
      eri_assert (sizeof (struct elf64_phdr) == a->val);
    else if (a->type == AT_PHNUM)
      phnum = a->val;
    else if (a->type == AT_PAGESZ)
      eri_assert (pagesize == a->val);

  eri_assert (base && phdr && phnum);

  uint64_t rel = 0, relsz = 0, pltrel = 0, pltrelsz = 0;
  const char *strtab = 0;
  const struct elf64_sym *symtab = 0;

  extern uint64_t _GLOBAL_OFFSET_TABLE_[] __attribute__ ((visibility ("hidden")));
  struct elf64_dyn *dyn = (struct elf64_dyn *) (base + _GLOBAL_OFFSET_TABLE_[0]);
  struct elf64_dyn *d;
  for (d = dyn; d->tag != DT_NULL; ++d)
    if (d->tag == DT_RELA)
      rel = d->val + base;
    else if (d->tag == DT_RELASZ)
      relsz = d->val;
    else if (d->tag == DT_JMPREL)
      pltrel = d->val + base;
    else if (d->tag == DT_PLTRELSZ)
      pltrelsz = d->val;
    else if (d->tag == DT_STRTAB)
      strtab = (const char *) (d->val + base);
    else if (d->tag == DT_SYMTAB)
      symtab = (const struct elf64_sym *) (d->val + base);

  if (rel + relsz == pltrel)
    relsz += pltrelsz;
  else if (pltrel)
    eri_assert (pltrelsz && rel + relsz == pltrel + pltrelsz);

  relocate (base, (const struct elf64_rela *) rel,
	    (const struct elf64_rela *) (rel + relsz),
	    symtab, strtab);

  uint64_t entry = 0;
  *basep = load_interp (ip->libname, &entry, pagesize);

  if (! disable)
    {
      ip->recorder = eri_get_recorder ();
      ip->recorder->init_process ("ers_data");
    }

  eri_assert (eri_printf ("ers_info libname %s ers_recorder %lu\n",
			  ip->libname, ip->recorder) == 0);
  return entry;
}
