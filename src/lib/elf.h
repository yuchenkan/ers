#ifndef LIB_ELF_H
#define LIB_ELF_H

#include <stdint.h>

#include <lib/syscall-common.h>

struct eri_auxv
{
  uint64_t type;
  union
    {
      void *ptr;
      uint64_t val;
    };
};

#define ERI_AT_NULL		0
#define ERI_AT_IGNORE		1
#define ERI_AT_EXECFD		2
#define ERI_AT_PHDR		3
#define ERI_AT_PHENT		4
#define ERI_AT_PHNUM		5
#define ERI_AT_PAGESZ		6
#define ERI_AT_BASE		7

#define ERI_AT_SYSINFO		32
#define ERI_AT_SYSINFO_EHDR	33

#define ERI_EI_NIDENT		16

struct eri_elf64_ehdr
{
  uint8_t ident[ERI_EI_NIDENT];
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

struct eri_elf64_phdr
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

#define ERI_ELFMAG		"\177ELF"
#define eri_assert_elf(ident) \
  eri_assert ((ident)[0] == *(char *) ERI_ELFMAG			\
	      && (ident)[1] == *((char *) ERI_ELFMAG + 1)		\
	      && (ident)[2] == *((char *) ERI_ELFMAG + 2)		\
	      && (ident)[3] == *((char *) ERI_ELFMAG + 3));

#define ERI_PF_X		0x1
#define ERI_PF_W		0x2
#define ERI_PF_R		0x4

#define ERI_PT_LOAD		1

#define eri_get_envp_from_args(args) \
  ({ void *_args = args; uint64_t _argc = *(uint64_t *) _args;		\
     (char **) _args + 1 + _argc + 1; })

struct eri_seg
{
  int32_t prot;

  uint64_t offset;
  uint64_t filesz;
  uint64_t vaddr;
  uint64_t memsz;
};

#define eri_seg_from_phdr(seg, phdr) \
  do {									\
    struct eri_seg *_seg = seg;						\
    struct eri_elf64_phdr *_phdr = phdr;				\
    _seg->prot = 0;							\
    if (_phdr->flags & ERI_PF_R) _seg->prot |= ERI_PROT_READ;		\
    if (_phdr->flags & ERI_PF_W) _seg->prot |= ERI_PROT_WRITE;		\
    if (_phdr->flags & ERI_PF_X) _seg->prot |= ERI_PROT_EXEC;		\
    _seg->offset = _phdr->offset;					\
    _seg->filesz = _phdr->filesz;					\
    _seg->vaddr = _phdr->vaddr;						\
    _seg->memsz = _phdr->memsz;						\
  } while (0)

#endif
