#ifndef ERI_RTLD_H
#define ERI_RTLD_H

#include <stdint.h>

#include "lib/syscall.h"

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
#define ERI_AT_IGNORE		0
#define ERI_AT_EXECFD		2
#define ERI_AT_PHDR		3
#define ERI_AT_PHENT		4
#define ERI_AT_PHNUM		5
#define ERI_AT_PAGESZ		6
#define ERI_AT_BASE		7

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

struct eri_seg_args
{
  int32_t prot;

  uint64_t offset;
  uint64_t filesz;
  uint64_t vaddr;
  uint64_t memsz;
};

struct eri_rtld_args
{
  uint64_t rdx;
  uint64_t rflags;

  uint64_t rsp;
  uint64_t rip;

  struct eri_sigset sig_mask;

  uint64_t map_start;
  uint64_t map_end;
};

#endif
