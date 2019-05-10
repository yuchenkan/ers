#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define eri_assert	assert

#include <lib/elf.h>
#include <lib/syscall-common.h>

static uint64_t
parse_elf (FILE *f, struct eri_seg **segs, uint16_t *nsegs,
	   struct eri_relative **rels, uint64_t *nrels)
{
  struct eri_elf64_ehdr ehdr;
  assert (fread (&ehdr, sizeof ehdr, 1, f) == 1);
  eri_assert_elf (ehdr.ident);

  assert (ehdr.phentsize == sizeof (struct eri_elf64_phdr));
  struct eri_elf64_phdr phdrs[ehdr.phnum];
  assert (fseek (f, ehdr.phoff, SEEK_SET) == 0);
  assert (fread (phdrs, ehdr.phentsize, ehdr.phnum, f) == ehdr.phnum);

  uint64_t i, j = 0;
  for (i = 0; i < ehdr.phnum; ++i)
    if (phdrs[i].type == ERI_PT_LOAD) ++j;

  *segs = calloc (j, sizeof **segs);
  *nsegs = j;

  j = 0;
  for (i = 0; i < ehdr.phnum; ++i)
    if (phdrs[i].type == ERI_PT_LOAD)
      eri_seg_from_phdr (*segs + j++, phdrs + i);

  assert (ehdr.shentsize == sizeof (struct eri_elf64_shdr));
  struct eri_elf64_shdr shdrs[ehdr.shnum];
  assert (fseek (f, ehdr.shoff, SEEK_SET) == 0);
  assert (fread (shdrs, ehdr.shentsize, ehdr.shnum, f) == ehdr.shnum);

  if (rels)
    {
      *rels = 0;
      *nrels = 0;
      for (i = 0; i < ehdr.shnum; ++i)
	if (shdrs[i].type == ERI_SHT_RELA)
	  {
	    *nrels = shdrs[i].size / sizeof (struct eri_elf64_rela);
	    struct eri_elf64_rela *relas = malloc (sizeof *relas * *nrels);
	    assert (fseek (f, shdrs[i].offset, SEEK_SET) == 0);
	    assert (fread (relas, sizeof relas[0], *nrels, f) == *nrels);
	    *rels = malloc (sizeof **rels * *nrels);
	    for (j = 0; j < *nrels; ++j)
	      {
		eri_assert (eri_elf64_r_type (relas[j].info)
						  == R_X86_64_RELATIVE);
		(*rels)[j].offset = relas[j].offset;
		(*rels)[j].addend = relas[j].addend;
	      }
	    free (relas);
	    break;
	  }
    }

  return ehdr.entry;
}

static void
convert_bin (const char *elf, const char *bin)
{
  FILE *ef = fopen (elf, "rb");
  assert (ef);

  struct eri_seg *segs;
  uint16_t nsegs;
  struct eri_relative *rels;
  uint64_t nrels;
  uint64_t entry = parse_elf (ef, &segs, &nsegs, &rels, &nrels);

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

  assert (fseek (bf, 0, SEEK_END) == 0);
  /* XXX: endianess */
  assert (fwrite (segs, sizeof segs[0], nsegs, bf) == nsegs);
  assert (fwrite (rels, sizeof rels[0], nrels, bf) == nrels);
  assert (fwrite (&nsegs, sizeof nsegs, 1, bf) == 1);
  assert (fwrite (&nrels, sizeof nrels, 1, bf) == 1);
  assert (fwrite (&entry, sizeof entry, 1, bf) == 1);

  fclose (bf);
  free (segs);
  free (rels);
  fclose (ef);
}

static void
convert_header (const char *elf, const char *header)
{
  FILE *ef = fopen (elf, "rb");
  assert (ef);

  struct eri_seg *segs;
  uint16_t nsegs;
  uint64_t entry = parse_elf (ef, &segs, &nsegs, 0, 0);

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

int32_t
main (int32_t argc, const char **argv)
{
  assert (argc >= 2);
  const char *t = argv[1];

  if (strcmp (t, "bin") == 0)
    {
      assert (argc == 4);
      convert_bin (argv[2], argv[3]);
    }
  else if (strcmp (t, "header") == 0)
    {
      assert (argc == 4);
      convert_header (argv[2], argv[3]);
    }
  else assert (0);

  return 0;
}
