#include <assert.h>
#include <stdio.h>

#include <common.h>
#include <lib/printf.h>

int32_t
main (int32_t argc, const char **argv)
{
  assert (argc <= 2);
  const char *name = argc == 2 ? argv[1] : "ers-data/t000";
  uint8_t buf[16 * 1024];
  eri_file_t file;
  if (eri_fopen (name, 1, &file, buf, sizeof buf))
    {
      fprintf (stderr, "failed to open %s\n", name);
      return 1;
    }

  uint8_t mark;
  while (eri_unserialize_uint8_or_eof (file, &mark))
    if (mark == ERI_INIT_RECORD)
      {
	printf ("ERI_INIT_RECORD\n");
	struct eri_init_record rec;
	eri_unserialize_init_record (file, &rec);
	printf ("  ver: %lu", rec.ver);
	printf ("  rdx: 0x%lx, rsp: 0x%lx, rip: 0x%lx\n",
		rec.rdx, rec.rsp, rec.rip);
	printf ("  sig_mask: 0x%lx\n", rec.sig_mask.val[0]);
	printf ("  sig_alt_stack.sp: 0x%lx, .flags: 0x%x, .size: %lu\n",
		rec.sig_alt_stack.sp, rec.sig_alt_stack.flags,
		rec.sig_alt_stack.size);
	printf ("  user_pid: %u\n", rec.user_pid);
	printf ("  start: 0x%lx, end: 0x%lx\n", rec.start, rec.end);
	printf ("  atomic_table_size: %lu\n", rec.atomic_table_size);
      }
    else if (mark == ERI_INIT_MAP_RECORD)
      {
	printf ("ERI_INIT_MAP_RECORD\n");
	struct eri_init_map_record rec;
	eri_unserialize_init_map_record (file, &rec);
	printf ("  start: 0x%lx, end: 0x%lx, prot: %u, grows_down %u\n",
		rec.start, rec.end, rec.prot, rec.grows_down);
	uint8_t i;
	for (i = 0; i < rec.data_count; ++i)
	  {
	    uint64_t start = eri_unserialize_uint64 (file);
	    uint64_t end = eri_unserialize_uint64 (file);
	    printf ("    data.start: 0x%lx, .end: 0x%lx\n", start, end);
	    eri_unserialize_skip_uint8_array (file, end - start);
	  }
      }
#if 0
    else if (mark == ERI_ASYNC_RECORD)
      {
	printf ("ERI_ASYNC_RECORD\n");
	struct eri_signal_record sig;
	assert (fread (&sig, sizeof sig, 1, f) == 1);
	printf ("  sig: %d, code: %d\n", sig.info.sig, sig.info.code);
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

	/* TODO */
	if (magic == ERI_SYSCALL_CLONE_MAGIC)
	  {
	    struct eri_syscall_clone_record sys;
	    read_without_magic (&sys, f);
	    printf ("  syscall.clone.result: %lu, ..id: %lu\n",
		    sys.result, sys.id);
	  }
	else if (magic == ERI_SYNC_ASYNC_MAGIC)
	  {
	    struct eri_sync_async_record sync;
	    read_without_magic (&sync, f);
	    printf ("  sync_async.steps: %lu\n", sync.steps);
	  }
	else if (magic == ERI_ATOMIC_MAGIC)
	  {
	    struct eri_atomic_record at;
	    read_without_magic (&at, f);
	    printf ("  atomic.updated: %u, .ver: %lu %lu, .val: 0x%lx\n",
		    at.updated, at.ver[0], at.ver[1], at.val);
	  }
	else assert (0);
      }
    else assert (0);
#endif

  eri_assert_fclose (file);
  return 0;
}
