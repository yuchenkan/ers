#include <assert.h>
#include <stdio.h>

#include <record.h>

int32_t
main (int32_t argc, const char **argv)
{
  assert (argc <= 2);
  const char *name = argc == 2 ? argv[1] : "ers-data/t000";
  FILE *f = fopen (name, "rb");
  if (! f)
    {
      printf ("failed to open %s\n", name);
      return 1;
    }

  uint8_t mark;
  while (fread (&mark, sizeof mark, 1, f))
    if (mark == ERI_INIT_RECORD)
      {
	printf ("ERI_INIT_RECORD\n");
	struct eri_init_record init;
	assert (fread (&init, sizeof init, 1, f) == 1);
	printf ("  ver: %lu", init.ver);
	printf ("  rdx: 0x%lx, rsp: 0x%lx, rip: 0x%lx\n",
		init.rdx, init.rsp, init.rip);
	printf ("  start: 0x%lx, end: 0x%lx\n", init.start, init.end);
      }
    else if (mark == ERI_INIT_MAP_RECORD)
      {
	printf ("ERI_INIT_MAP_RECORD\n");
	struct eri_init_map_record init_map;
	assert (fread (&init_map, sizeof init_map, 1, f) == 1);
	printf ("  start: 0x%lx, end: 0x%lx, perms: %u\n",
		 init_map.start, init_map.end, init_map.perms);
	uint8_t i;
	for (i = 0; i < init_map.data_count; ++i)
	  {
	    struct eri_init_map_data_record data;
	    assert (fread (&data, sizeof data, 1, f) == 1);
	    printf ("    data.start: 0x%lx, data.end: 0x%lx\n",
		     data.start, data.end);
	    assert (fseek (f, data.end - data.start, SEEK_CUR) == 0);
	  }
      }
    else if (mark == ERI_SYNC_RECORD)
      printf ("ERI_SYNC_RECORD\n");
    else if (mark == ERI_ASYNC_RECORD)
      printf ("ERI_ASYNC_RECORD\n");
    else assert (0);

  fclose (f);
  return 0;
}