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
  const char *bin = argv[2];

  FILE *ef = fopen (elf, "rb");
  assert (ef);

  struct eri_seg *segs;
  uint16_t nsegs;
  uint64_t entry = eri_parse_elf (ef, &segs, &nsegs);

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
  assert (fwrite (&nsegs, sizeof nsegs, 1, bf) == 1);
  assert (fwrite (&entry, sizeof entry, 1, bf) == 1);

  fclose (bf);
  free (segs);
  fclose (ef);
  return 0;
}
