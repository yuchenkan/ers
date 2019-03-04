#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define eri_assert	assert

#include <lib/elf.h>
#include <lib/syscall.h>

static uint64_t
parse_elf (FILE *f, struct eri_seg **segs, uint16_t *nsegs)
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

  *segs = malloc (sizeof **segs * j);
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

static void
convert_live (const char *elf, const char *bin, const char *header)
{
  FILE *ef = fopen (elf, "rb");
  assert (ef);

  struct eri_seg *segs;
  uint16_t nsegs;
  uint64_t entry = parse_elf (ef, &segs, &nsegs);

  FILE *bf = fopen (bin, "wb");
  assert (bf);

  uint16_t i;
  for (i = 0; i < nsegs; ++i)
    {
      assert (fseek (ef, segs[i].offset, SEEK_SET) == 0);
      assert (fseek (bf, segs[i].offset, SEEK_SET) == 0);

      uint8_t b[segs[i].filesz];
      assert (fread (b, segs[i].filesz, 1, ef) == 1);
      assert (fwrite (b, segs[i].filesz, 1, bf) == 1);
    }

  FILE *hf = fopen (header, "w");
  assert (hf);

  fprintf (hf, "#define ERI_LIVE_SEGMENTS\t{ ");
  for (i = 0; i < nsegs; ++i)
    fprintf (hf, "{ %d, %lu, %lu, %lu, %lu }, ", segs[i].prot,
	     segs[i].offset, segs[i].filesz, segs[i].vaddr, segs[i].memsz);
  fprintf (hf, " }\n");
  fprintf (hf, "#define ERI_LIVE_START\t%lu\n", entry);

  fclose (hf);
  fclose (bf);
  free (segs);
  fclose (ef);
}

static void
convert_rtld (const char *elf, const char *header)
{
  FILE *ef = fopen (elf, "rb");
  assert (ef);

  struct eri_seg *segs;
  uint16_t nsegs;
  uint64_t entry = parse_elf (ef, &segs, &nsegs);

  assert (nsegs == 1);
  assert (segs[0].filesz == segs[0].memsz);
  entry = entry - segs[0].vaddr;
  uint64_t offset = segs[0].offset + entry;
  uint64_t sz = segs[0].filesz - entry;

  uint8_t b[sz];
  assert (fseek (ef, offset, SEEK_SET) == 0);
  assert (fread (b, sz, 1, ef) == 1);

  FILE *hf = fopen (header, "w");
  fprintf (hf, "#define _ERS_LIVE_RTLD\t.byte");
  uint64_t i;
  for (i = 0; i < sz; ++i)
    {
      if (i != 0) fprintf (hf, ",");
      fprintf (hf, " %u", b[i]);
    }

  fclose (hf);
  free (segs);
  fclose (ef);
}

int
main (int argc, const char **argv)
{
  assert (argc >= 2);
  const char *t = argv[1];

  if (strcmp (t, "live") == 0)
    {
      assert (argc == 5);
      convert_live (argv[2], argv[3], argv[4]);
    }
  else if (strcmp (t, "live-rtld") == 0)
    {
      assert (argc == 4);
      convert_rtld (argv[2], argv[3]);
    }
  else assert (0);

  return 0;
}
