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
    else if (mark == ERI_ASYNC_RECORD)
      {
	printf ("ERI_ASYNC_RECORD\n");
	struct eri_signal_record rec;
	eri_unserialize_signal_record (file, &rec);
	printf ("  in: %lu, act_ver: %lu, info.sig: %d, info.code: %d\n",
		rec.in, rec.act_ver, rec.info.sig, rec.info.code);
      }
    else if (mark == ERI_SYNC_RECORD)
      {
	printf ("ERI_SYNC_RECORD\n");
	uint16_t magic = eri_unserialize_magic (file);
	if (magic == ERI_SYSCALL_RESULT_MAGIC)
	  printf ("  syscall.result: %ld\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_IN_MAGIC)
	  printf ("  syscall.in: 0x%lx\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_OUT_MAGIC)
	  printf ("  syscall.out: 0x%lx\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_CLONE_MAGIC)
	  {
	    struct eri_syscall_clone_record rec;
	    eri_unserialize_syscall_clone_record (file, &rec);
	    printf ("  syscall.clone.out: %lu, ..result: %ld",
		    rec.out, rec.result);
	    if (! eri_syscall_is_error (rec.result))
	      printf (", ..id: 0x%lx\n", rec.id);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_RT_SIGACTION_MAGIC)
	  printf ("  syscall.rt_sigaction: %lu\n",
		  eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_RT_SIGPENDING_MAGIC)
	  {
	    struct eri_syscall_rt_sigpending_record rec;
	    eri_unserialize_syscall_rt_sigpending_record (file, &rec);
	    printf ("  syscall.rt_sigpending.result: %ld", rec.result);
	    if (! eri_syscall_is_error (rec.result))
	      printf (", ..in: %lu, ..set: 0x%lx\n", rec.in, rec.set.val[0]);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_KILL_MAGIC)
	  {
	    struct eri_syscall_kill_record rec;
	    eri_unserialize_syscall_kill_record (file, &rec);
	    printf ("  syscall.kill.out: %lu, ..result: %ld, ..in: %lu\n",
		    rec.out, rec.result, rec.in);
	  }
	else if (magic == ERI_SYNC_ASYNC_MAGIC)
	  printf ("  sync_async.steps: %lu\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_ATOMIC_MAGIC)
	  {
	    struct eri_atomic_record rec;
	    eri_unserialize_atomic_record (file, &rec);
	    printf ("  atomic.updated: %u, .ver: %lu %lu, .val: 0x%lx\n",
		    rec.updated, rec.ver[0], rec.ver[1], rec.val);
	  }
      }
    else eri_assert_unreachable ();

  eri_assert_fclose (file);
  return 0;
}
