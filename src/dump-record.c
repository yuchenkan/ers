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
	printf ("  sig_mask: 0x%lx\n", init.sig_mask.val[0]);
	printf ("  start: 0x%lx, end: 0x%lx\n", init.start, init.end);
      }
    else if (mark == ERI_INIT_MAP_RECORD)
      {
	printf ("ERI_INIT_MAP_RECORD\n");
	struct eri_init_map_record init_map;
	assert (fread (&init_map, sizeof init_map, 1, f) == 1);
	printf ("  start: 0x%lx, end: 0x%lx, prot: %u, grows_down %u\n",
		init_map.start, init_map.end,
		init_map.prot, init_map.grows_down);
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
      {
	printf ("ERI_SYNC_RECORD\n");
	uint8_t magic;
	assert (fread (&magic, sizeof magic, 1, f) == 1);
	if (magic == ERI_SYNC_ASYNC_MAGIC)
	  {
	    uint64_t steps;
	    assert (fread (&steps, sizeof steps, 1, f) == 1);
	    printf ("  sync_async.steps: %lu\n", steps);
	  }
	else if (magic == ERI_ATOMIC_MAGIC)
	  {
	    uint64_t v[2];
	    assert (fread (v, sizeof v, 1, f) == 1);
	    printf ("  atomic.ver: %lu %lu\n", v[0], v[1]);
	  }
	else if (magic == ERI_ATOMIC_LOAD_MAGIC)
	  {
	    uint64_t v[3];
	    assert (fread (v, sizeof v, 1, f) == 1);
	    printf ("  atomic_load.ver: %lu %lu\n", v[0], v[1]);
	    printf ("  atomic_load.val: 0x%lx\n", v[2]);
	  }
	/* TODO */
      }
    else if (mark == ERI_ASYNC_RECORD)
      {
	printf ("ERI_ASYNC_RECORD\n");
	struct eri_siginfo info;
	assert (fread (&info, sizeof info, 1, f) == 1);
	printf ("  sig: %d, code: %d\n", info.sig, info.code);
      }
    else assert (0);

  fclose (f);
  return 0;
}
