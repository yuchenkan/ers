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
	printf ("  atomic_table_size: %lu\n", init.atomic_table_size);
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
#define read_without_magic(t, f) \
  do { typeof (t) _t = t;						\
       assert (fread ((uint8_t *) _t + sizeof (uint8_t),		\
		      sizeof *_t - sizeof (uint8_t), 1, f) == 1);	\
  } while (0)

	if (magic == ERI_SYNC_ASYNC_MAGIC)
	  {
	    struct eri_sync_async_record sync;
	    read_without_magic (&sync, f);
	    printf ("  sync_async.steps: %lu\n", sync.steps);
	  }
	else if (magic == ERI_ATOMIC_MAGIC)
	  {
	    struct eri_atomic_record at;
	    read_without_magic (&at, f);
	    printf ("  atomic.updated: %u\n", at.updated);
	    printf ("  atomic_load.ver: %lu %lu\n", at.ver[0], at.ver[1]);
	    printf ("  atomic_load.val: 0x%lx\n", at.val);
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
