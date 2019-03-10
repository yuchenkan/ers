#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <convert-common.h>

#include <lib/elf.h>

int
main (int argc, const char **argv)
{
  assert (argc == 3);
  const char *elf = argv[1];
  const char *header = argv[2];

  FILE *ef = fopen (elf, "rb");
  assert (ef);

  struct eri_seg *segs;
  uint16_t nsegs;
  uint64_t entry = eri_parse_elf (ef, &segs, &nsegs);

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

  return 0;
}
