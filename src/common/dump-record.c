#include <assert.h>
#include <stdio.h>

#include <lib/printf.h>
#include <common/common.h>

static uint8_t
copy_skip (void *args, void *dst, const void *src, uint64_t size)
{
  return 0;
}

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
	printf ("  map_start: 0x%lx, map_end: 0x%lx\n",
		rec.map_start, rec.map_end);
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
	printf ("  in: %lu, info.sig: %d", rec.in, rec.info.sig);
	if (rec.info.sig)
	  printf (", .code; %d, act.ver: %lu\n", rec.info.code, rec.act.ver);
	else printf ("\n");
      }
    else if (mark == ERI_SYNC_RECORD)
      {
	printf ("ERI_SYNC_RECORD\n");
	uint16_t magic = eri_unserialize_magic (file);
	if (magic == ERI_SIGNAL_MAGIC)
	  {
	    struct eri_ver_sigaction act;
	    eri_unserialize_ver_sigaction (file, &act);
	    printf ("  signal.act.ver: %lu\n", act.ver);
	  }
	else if (magic == ERI_SYSCALL_RESULT_MAGIC)
	  printf ("  syscall.result: %ld\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_IN_MAGIC)
	  printf ("  syscall.in: %lu\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_OUT_MAGIC)
	  printf ("  syscall.out: %lu\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_RESULT_IN_MAGIC)
	  {
	    uint64_t rec[2];
	    eri_unserialize_uint64_array (file, rec, eri_length_of (rec));
	    printf ("  syscall.result: %ld, .in: %lu\n", rec[0], rec[1]);
	  }
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
	else if (magic == ERI_SYSCALL_RT_SIGACTION_SET_MAGIC)
	  printf ("  syscall.rt_sigaction: %lu\n",
		  eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_RT_SIGACTION_MAGIC)
	  {
	    struct eri_ver_sigaction act;
	    eri_unserialize_ver_sigaction (file, &act);
	    printf ("  syscall.rt_sigaction_get: %lu\n", act.ver);
	  }
	else if (magic == ERI_SYSCALL_RT_SIGPENDING_MAGIC)
	  {
	    struct eri_syscall_rt_sigpending_record rec;
	    eri_unserialize_syscall_rt_sigpending_record (file, &rec);
	    printf ("  syscall.rt_sigpending.result: %ld", rec.result);
	    if (! eri_syscall_is_error (rec.result))
	      printf (", ..in: %lu, ..set: 0x%lx\n", rec.in, rec.set.val[0]);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC)
	  {
	    struct eri_syscall_rt_sigtimedwait_record rec;
	    eri_unserialize_syscall_rt_sigtimedwait_record (file, &rec);
	    printf ("  syscall.rt_sigtimedwait.result: %ld", rec.result);
	    if (! eri_syscall_is_error (rec.result)
		|| rec.result == ERI_EINTR) printf (", ..in: %lu", rec.in);
	    if (! eri_syscall_is_error (rec.result) && rec.info.sig)
	      printf (", ..code: %d\n", rec.info.code);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_KILL_MAGIC)
	  {
	    struct eri_syscall_kill_record rec;
	    eri_unserialize_syscall_kill_record (file, &rec);
	    printf ("  syscall.kill.out: %lu, ..result: %ld, ..in: %lu\n",
		    rec.out, rec.result, rec.in);
	  }
	else if (magic == ERI_SYSCALL_READ_MAGIC
		 /* identical byte array in the file */
		 || magic == ERI_SYSCALL_READV_MAGIC)
	  {
	    struct eri_syscall_read_record rec = { .copy = copy_skip };
	    eri_unserialize_syscall_read_record (file, &rec);
	    printf ("  syscall.%s.result: %ld, ..in: %lu\n",
		    magic == ERI_SYSCALL_READ_MAGIC ? "read" : "readv",
		    rec.result, rec.in);
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
