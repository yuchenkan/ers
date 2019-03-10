#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <convert-common.h>

#include <lib/elf.h>
#include <lib/syscall.h>

uint64_t
eri_parse_elf (FILE *f, struct eri_seg **segs, uint16_t *nsegs)
{
  struct eri_elf64_ehdr ehdr;
  assert (fread (&ehdr, sizeof ehdr, 1, f) == 1);
  eri_assert_elf (ehdr.ident);

  assert (ehdr.phentsize == sizeof (struct eri_elf64_phdr));
  struct eri_elf64_phdr phdrs[ehdr.phnum];
  assert (fseek (f, ehdr.phoff, SEEK_SET) == 0);
  assert (fread (phdrs, ehdr.phentsize, ehdr.phnum, f) == ehdr.phnum);

  uint16_t i, j = 0;
  for (i = 0; i < ehdr.phnum; ++i)
    if (phdrs[i].type == ERI_PT_LOAD) ++j;

  *segs = calloc (j, sizeof **segs);
  *nsegs = j;
  for (i = 0; i < ehdr.phnum; ++i)
    if (phdrs[i].type == ERI_PT_LOAD)
      {
	int32_t prot = 0;
	if (phdrs[i].flags & ERI_PF_R) prot |= ERI_PROT_READ;
	if (phdrs[i].flags & ERI_PF_W) prot |= ERI_PROT_WRITE;
	if (phdrs[i].flags & ERI_PF_X) prot |= ERI_PROT_EXEC;
	(*segs)[i].prot = prot;

	(*segs)[i].offset = phdrs[i].offset;
	(*segs)[i].filesz = phdrs[i].filesz;
	(*segs)[i].vaddr = phdrs[i].vaddr;
	(*segs)[i].memsz = phdrs[i].memsz;
      }

  return ehdr.entry;
}

