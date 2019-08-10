#include <stdio.h>

#include <lib/util.h>
#include <lib/printf.h>
#include <common/debug.h>
#include <common/serial.h>

int32_t
main (int32_t argc, const char **argv)
{
  eri_xassert (argc <= 2, eri_info);
  const char *name = argc == 2 ? argv[1] : "ers-data/t000";
  uint8_t buf[16 * 1024];
  eri_file_t file;
  if (eri_fopen (name, 1, &file, buf, sizeof buf))
    {
      fprintf (stderr, "failed to open %s\n", name);
      return 1;
    }

  uint8_t mark;
  uint64_t i = 0;
  while (eri_unserialize_uint8_or_eof (file, &mark))
    if (mark == ERI_INIT_RECORD)
      {
	printf ("%lu %s\n", i++, eri_record_mark_str (mark));
	struct eri_init_record rec;
	eri_unserialize_init_record (file, &rec);
	printf ("  ver: %lu", rec.ver);
	printf ("  rdx: 0x%lx, rsp: 0x%lx, rip: 0x%lx\n",
		rec.rdx, rec.rsp, rec.rip);
	printf ("  brk: 0x%lx\n", rec.brk);
	printf ("  sig_mask: 0x%lx\n", rec.sig_mask);
	printf ("  sig_alt_stack.sp: 0x%lx, .flags: 0x%x, .size: %lu\n",
		rec.sig_alt_stack.sp, rec.sig_alt_stack.flags,
		rec.sig_alt_stack.size);
	printf ("  user_pid: %u\n", rec.user_pid);
	printf ("  map_range.start: 0x%lx, .end: 0x%lx\n",
		rec.map_range.start, rec.map_range.end);
	printf ("  atomic_table_size: %lu\n", rec.atomic_table_size);
      }
    else if (mark == ERI_INIT_MAP_RECORD)
      {
	printf ("%lu %s\n", i++, eri_record_mark_str (mark));
	struct eri_init_map_record rec;
	eri_unserialize_init_map_record (file, &rec);
	printf ("  start: 0x%lx, end: 0x%lx, prot: %u, "
		"grows_down: %u, type: %u",
		rec.start, rec.end, rec.prot, rec.grows_down, rec.type);
	if (rec.type == ERI_INIT_MAP_EMPTY) printf ("\n");
	else if (rec.type == ERI_INIT_MAP_FILE)
	  printf (", file_id: %lx\n", eri_unserialize_uint64 (file));
	else if (rec.type == ERI_INIT_MAP_STACK)
	  {
	    uint64_t start = eri_unserialize_uint64 (file);
	    printf (", data_start: %lx\n", start);
	    eri_unserialize_skip_uint8_array (file, rec.end - start);
	  }
	else eri_assert_unreachable ();
      }
    else if (mark == ERI_ASYNC_RECORD)
      {
	printf ("%lu %s\n", i++, eri_record_mark_str (mark));
	struct eri_async_signal_record rec;
	eri_unserialize_async_signal_record (file, &rec);
	printf ("  in: %lu, info.sig: %d", rec.in, rec.info.sig);
	if (rec.info.sig)
	  printf (", .code: %d, act.ver: %lu\n", rec.info.code, rec.act.ver);
	else printf ("\n");
      }
    else if (mark == ERI_SYSCALL_RESTART_OUT_RECORD)
      {
	printf ("%lu %s\n", i++, eri_record_mark_str (mark));
	printf ("  syscall.restart.out: %lu\n", eri_unserialize_uint64 (file));
      }
    else if (mark == ERI_SYNC_RECORD)
      {
	printf ("%lu %s\n", i++, eri_record_mark_str (mark));
	uint16_t magic = eri_unserialize_magic (file);
	printf ("magic: %s\n", eri_record_magic_str (magic));
	if (magic == ERI_SIGNAL_MAGIC)
	  {
	    struct eri_sig_act act;
	    eri_unserialize_sig_act (file, &act);
	    printf ("  signal.act.ver: %lu\n", act.ver);
	  }
	else if (magic == ERI_SYSCALL_RESULT_MAGIC)
	  printf ("  syscall.result: %ld\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_IN_MAGIC)
	  printf ("  syscall.in: %lu\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_OUT_MAGIC)
	  printf ("  syscall.out: %lu\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_RES_IN_MAGIC)
	  {
	    struct eri_syscall_res_in_record rec;
	    eri_unserialize_syscall_res_in_record (file, &rec);
	    printf ("  syscall.result: %ld, .in: %lu\n", rec.result, rec.in);
	  }
	else if (magic == ERI_SYSCALL_RES_IO_MAGIC)
	  {
	    struct eri_syscall_res_io_record rec;
	    eri_unserialize_syscall_res_io_record (file, &rec);
	    printf ("  syscall.out: %lu, .result: %ld, .in: %lu\n",
		    rec.out, rec.res.result, rec.res.in);
	  }
	else if (magic == ERI_SYSCALL_CLONE_MAGIC)
	  {
	    struct eri_syscall_clone_record rec;
	    eri_unserialize_syscall_clone_record (file, &rec);
	    printf ("  syscall.clone.out: %lu, ..result: %ld",
		    rec.out, rec.result);
	    if (eri_syscall_is_ok (rec.result))
	      printf (", ..id: 0x%lx\n", rec.id);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_EXIT_MAGIC)
	  {
	    struct eri_syscall_exit_record rec;
	    eri_unserialize_syscall_exit_record (file, &rec);
	    printf ("  syscall.exit.out: %lu\n", rec.out);
	    if (rec.clear_tid.ok)
	      printf ("  syscall.exit.clear_tid.ver: %lu %lu\n",
		      rec.clear_tid.ver.first, rec.clear_tid.ver.second);
	  }
	else if (magic == ERI_SYSCALL_RT_SIGACTION_SET_MAGIC)
	  printf ("  syscall.rt_sigaction: %lu\n",
		  eri_unserialize_uint64 (file));
	else if (magic == ERI_SYSCALL_RT_SIGACTION_MAGIC)
	  {
	    struct eri_sigaction act;
	    eri_unserialize_sigaction (file, &act);
	    uint64_t ver = eri_unserialize_uint64 (file);
	    printf ("  syscall.rt_sigaction_get: %lu\n", ver);
	  }
	else if (magic == ERI_SYSCALL_RT_SIGPENDING_MAGIC)
	  {
	    struct eri_syscall_rt_sigpending_record rec;
	    eri_unserialize_syscall_rt_sigpending_record (file, &rec);
	    printf ("  syscall.rt_sigpending.result: %ld, ..in: %lu",
		    rec.res.result, rec.res.in);
	    if (eri_syscall_is_ok (rec.res.result))
	      printf (", ..set: 0x%lx\n", rec.set);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC)
	  {
	    struct eri_syscall_rt_sigtimedwait_record rec;
	    eri_unserialize_syscall_rt_sigtimedwait_record (file, &rec);
	    printf ("  syscall.rt_sigtimedwait.result: %ld, ..in: %lu",
		    rec.res.result, rec.res.in);
	    if (eri_syscall_is_ok (rec.res.result) && rec.info.sig)
	      printf (", ..code: %d\n", rec.info.code);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_STAT_MAGIC)
	  {
	    struct eri_syscall_stat_record rec;
	    eri_unserialize_syscall_stat_record (file, &rec);
	    printf ("  syscall.stat.result: %ld, ..in: %lu\n",
		    rec.res.result, rec.res.in);
	  }
	else if (magic == ERI_SYSCALL_UNAME_MAGIC)
	  {
	    struct eri_syscall_uname_record rec;
	    eri_unserialize_syscall_uname_record (file, &rec);
	    printf ("  syscall.uname.result: %ld, ..in: %lu, "
		    "..utsname.sysname: %s, ...nodename: %s, "
		    "...release: %s, ...version: %s, ...machine: %s, "
		    "...domainname: %s\n",
		    rec.res.result, rec.res.in, rec.utsname.sysname,
		    rec.utsname.nodename, rec.utsname.release,
		    rec.utsname.version, rec.utsname.machine,
		    rec.utsname.domainname);
	  }
        else if (magic == ERI_SYSCALL_TIMES_MAGIC)
	  {
	    struct eri_syscall_times_record rec;
	    eri_unserialize_syscall_times_record (file, &rec);
	    printf ("  syscall.times.result: %ld, ..in: %lu",
		    rec.res.result, rec.res.in);
	    if (eri_syscall_is_fault_or_ok (rec.res.result))
	      printf (", ..tms.utime: %ld, ...stime: %ld, "
		      "...cutime: %ld, ...cstime: %ld\n",
		      rec.tms.utime, rec.tms.stime,
		      rec.tms.cutime, rec.tms.cstime);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_GETTIMEOFDAY_MAGIC)
	  {
	    struct eri_syscall_gettimeofday_record rec;
	    eri_unserialize_syscall_gettimeofday_record (file, &rec);
	    printf ("  syscall.times.result: %ld, ..in: %lu",
		    rec.res.result, rec.res.in);
	    if (eri_syscall_is_fault_or_ok (rec.res.result))
	      printf (", ..time.sec: %ld, ...usec: %ld\n",
		      rec.time.sec, rec.time.usec);
	    else printf ("\n");
	  }
        else if (magic == ERI_SYSCALL_CLOCK_GETTIME_MAGIC)
	  {
	    struct eri_syscall_clock_gettime_record rec;
	    eri_unserialize_syscall_clock_gettime_record (file, &rec);
	    printf ("  syscall.clock_gettime.result: %ld, ..in: %lu",
		    rec.res.result, rec.res.in);
	    if (eri_syscall_is_fault_or_ok (rec.res.result))
	      printf ("..time.sec: %ld, ...nsec: %ld\n",
		      rec.time.sec, rec.time.nsec);
	    else printf ("\n");
	  }
        else if (magic == ERI_SYSCALL_GETRLIMIT_MAGIC)
	  {
	    struct eri_syscall_getrlimit_record rec;
	    eri_unserialize_syscall_getrlimit_record (file, &rec);
	    printf ("  syscall.getrlimit.result: %ld, ..in: %lu",
		    rec.res.result, rec.res.in);
	    if (eri_syscall_is_fault_or_ok (rec.res.result))
	      printf ("..rlimit.cur: %lu, ...max: %lu\n",
		      rec.rlimit.cur, rec.rlimit.max);
	    else printf ("\n");
	  }
        else if (magic == ERI_SYSCALL_PRLIMIT64_MAGIC)
	  {
	    struct eri_syscall_prlimit64_record rec;
	    eri_unserialize_syscall_prlimit64_record (file, &rec);
	    printf ("  syscall.prlimit64.out: %lu, ..result: %ld, ..in: %lu",
		    rec.out, rec.res.result, rec.res.in);
	    if (eri_syscall_is_fault_or_ok (rec.res.result))
	      printf ("..rlimit.cur: %lu, ...max: %lu\n",
		      rec.rlimit.cur, rec.rlimit.max);
	    else printf ("\n");
	  }
        else if (magic == ERI_SYSCALL_GETRUSAGE_MAGIC)
	  {
	    struct eri_syscall_getrusage_record rec;
	    eri_unserialize_syscall_getrusage_record (file, &rec);
	    printf ("  syscall.getrusage.result: %ld, ..in: %lu\n",
		    rec.res.result, rec.res.in);
	    if (eri_syscall_is_fault_or_ok (rec.res.result))
	      {
		printf ("  syscall.getrusage.rusage.utime.sec: %ld, "
			"....usec: %ld\n",
			rec.rusage.utime.sec, rec.rusage.utime.usec);
		printf ("  syscall.getrusage.rusage.stime.sec: %ld, "
			"....usec: %ld\n",
			rec.rusage.stime.sec, rec.rusage.stime.usec);
		printf ("  syscall.getrusage.rusage.maxrss: %ld, "
			"...ixrss: %ld, ...idrss: %ld, ...isrss: %ld, "
			"...minflt: %ld, ...majflt: %ld, ...nswap: %ld, "
			"...inblock: %ld, ...oublock: %ld, ...msgsnd: %ld, "
			"...msgrcv: %ld, ...nsignals: %ld, ...nvcsw: %ld, "
			"...nivcsw: %ld\n",
			rec.rusage.maxrss, rec.rusage.ixrss,
			rec.rusage.idrss, rec.rusage.isrss,
			rec.rusage.minflt, rec.rusage.majflt,
			rec.rusage.nswap, rec.rusage.inblock,
			rec.rusage.oublock, rec.rusage.msgsnd,
			rec.rusage.msgrcv, rec.rusage.nsignals,
			rec.rusage.nvcsw, rec.rusage.nivcsw);
	      }
	  }
	else if (magic == ERI_SYSCALL_ACCEPT_MAGIC)
	  {
	    struct eri_syscall_accept_record rec;
	    eri_unserialize_syscall_accept_record (file, &rec);
	    printf ("  syscall.accept.out: %ld, ..result: %ld, ..in: %ld\n",
		    rec.out, rec.res.result, rec.res.in);
	    if (rec.addrlen)
	      printf ("  syscall.accept.addr.family: %hu\n",
		      rec.addr.family);
	  }
	else if (magic == ERI_SYSCALL_GETSOCKNAME_MAGIC)
	  {
	    struct eri_syscall_getsockname_record rec;
	    eri_unserialize_syscall_getsockname_record (file, &rec);
	    printf ("  syscall.getsockname.result: %ld, ..in: %ld\n",
		    rec.res.result, rec.res.in);
	    if (rec.addrlen)
	      printf ("  syscall.getsockname.addr.family: %hu\n",
		      rec.addr.family);
	  }
	else if (magic == ERI_SYSCALL_USTAT_MAGIC)
	  {
	    struct eri_syscall_ustat_record rec;
	    eri_unserialize_syscall_ustat_record (file, &rec);
	    printf ("  syscall.ustat.result: %ld, ..in: %ld\n",
		    rec.res.result, rec.res.in);
	  }
	else if (magic == ERI_SYSCALL_STATFS_MAGIC)
	  {
	    struct eri_syscall_statfs_record rec;
	    eri_unserialize_syscall_statfs_record (file, &rec);
	    printf ("  syscall.statfs.result: %ld, ..in: %ld\n",
		    rec.res.result, rec.res.in);
	  }
	else if (magic == ERI_SYSCALL_PIPE_MAGIC)
	  {
	    struct eri_syscall_pipe_record rec;
	    eri_unserialize_syscall_pipe_record (file, &rec);
	    printf ("  syscall.pipe.out: %ld, ..result: %ld, ..in: %ld",
		    rec.out, rec.res.result, rec.res.in);
	    if (eri_syscall_is_ok (rec.res.result))
	      printf (", ..pipe: %d %d\n", rec.pipe[0], rec.pipe[1]);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_FUTEX_MAGIC)
	  {
	    struct eri_syscall_futex_record rec;
	    eri_unserialize_syscall_futex_record (file, &rec);
	    printf ("  syscall.futex.result: %ld, ..in: %lu\n",
		    rec.res.result, rec.res.in);
	    if (rec.atomic.ok)
	      printf (" syscall.futex.atomic.ver: %lu %lu\n",
		      rec.atomic.ver.first, rec.atomic.ver.second);
	  }
	else if (magic == ERI_SYSCALL_FUTEX_REQUEUE_MAGIC)
	  {
	    struct eri_syscall_futex_requeue_record rec;
	    eri_unserialize_syscall_futex_requeue_record (file, &rec);
	    printf ("  syscall.futex_requeue.result: %ld, ..in: %lu, "
		    "..cmp: %u\n",
		    rec.res.result, rec.res.in, rec.cmp);
	    if (rec.cmp && rec.atomic.ok)
	      printf ("  syscall.futex_requeue.atomic.ver: %lu %lu\n",
		      rec.atomic.ver.first, rec.atomic.ver.second);
	  }
	else if (magic == ERI_SYSCALL_GETRANDOM_RANDOM_MAGIC)
	  {
	    uint64_t res = eri_unserialize_uint64 (file);
	    printf ("  syscall.getrandom_random.result: %ld", res);
	    if (eri_syscall_is_fault_or_ok (res))
	      {
		uint64_t len = eri_unserialize_uint64 (file);
		printf (", ..len: %ld\n", len);
		eri_unserialize_skip_uint8_array (file, len);
	      }
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_GETRANDOM_URANDOM_MAGIC)
	  {
	    uint64_t len = 0;
	    while (1)
	      {
		uint64_t l = eri_unserialize_uint64 (file);
		if (l == 0) break;
		eri_unserialize_skip_uint8_array (file, l);
		len += l;
	      }
	    uint64_t res = eri_unserialize_uint64 (file);
	    printf ("  syscall.getrandom_urandom.result: %ld", res);
	    if (len) printf (", ..len: %ld\n", len);
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_READ_MAGIC)
	  {
	    struct eri_syscall_res_in_record rec;
	    eri_unserialize_syscall_res_in_record (file, &rec);
	    uint64_t off = 0;
	    if (eri_syscall_is_ok (rec.result) && rec.result)
	      {
		uint64_t size;
		while ((size = eri_unserialize_uint64 (file)))
		  {
		    eri_unserialize_skip_uint8_array (file, size);
		    off += size;
		  }
	      }
	    printf ("  syscall.read.result: %ld, ..in: %lu, ..off: %lu\n",
		    rec.result, rec.in, off);
	  }
	else if (magic == ERI_SYSCALL_MMAP_MAGIC)
	  {
	    struct eri_syscall_res_in_record rec;
	    eri_unserialize_syscall_res_in_record (file, &rec);
	    printf ("  syscall.mmap.result: %ld, ..in: %lu",
		    rec.result, rec.in);
	    if (eri_syscall_is_ok (rec.result))
	      {
		uint64_t id = eri_unserialize_uint64 (file);
		uint8_t ok = id ? eri_unserialize_uint8 (file) : 1;
		printf (",..id: %lx, ..ok: %d\n", id, ok);
	      }
	    else printf ("\n");
	  }
	else if (magic == ERI_SYSCALL_GETCWD_MAGIC)
	  {
	    struct eri_syscall_res_in_record rec;
	    eri_unserialize_syscall_res_in_record (file, &rec);
	    printf ("  syscall.getcwd.result: %ld, ..in: %lu\n",
		    rec.result, rec.in);
	    if (eri_syscall_is_fault_or_ok (rec.result))
	      {
	        uint64_t len = eri_unserialize_uint64 (file);
		eri_unserialize_skip_uint8_array (file, len);
	      }
	  }
	else if (magic == ERI_SYSCALL_SELECT_MAGIC)
	  {
	    struct eri_syscall_res_in_record rec;
	    eri_unserialize_syscall_res_in_record (file, &rec);
	    uint8_t flags = eri_unserialize_uint8 (file);
	    printf ("  syscall.select.result: %ld, ..in: %lu, ..flags: 0x%x",
		    rec.result, rec.in, flags);
	    if (eri_syscall_is_fault_or_ok (rec.result))
	      {
		uint32_t size = eri_unserialize_uint32 (file);
		printf (", ..size: %u\n", size);
		if (flags & ERI_SYSCALL_SELECT_READ)
		  eri_unserialize_skip_uint8_array (file, size);
		if (flags & ERI_SYSCALL_SELECT_WRITE)
		  eri_unserialize_skip_uint8_array (file, size);
		if (flags & ERI_SYSCALL_SELECT_EXCEPT)
		  eri_unserialize_skip_uint8_array (file, size);
	      }
	    else printf ("\n");

	    if (flags & ERI_SYSCALL_SELECT_TIMEVAL)
	      {
		struct eri_timeval time;
		eri_unserialize_timeval (file, &time);
	      }
	    else if (flags & ERI_SYSCALL_SELECT_TIMESPEC)
	      {
		struct eri_timespec time;
		eri_unserialize_timespec (file, &time);
	      }
	  }
	else if (magic == ERI_SYNC_ASYNC_MAGIC)
	  printf ("  sync_async.steps: %lu\n", eri_unserialize_uint64 (file));
	else if (magic == ERI_ATOMIC_MAGIC)
	  {
	    struct eri_atomic_record rec;
	    eri_unserialize_atomic_record (file, &rec);
	    printf ("  atomic.ok: %u\n", rec.ok);
	    if (rec.ok)
	      printf ("  atomic.ver: %lu %lu\n",
		      rec.ver.first, rec.ver.second);
	  }
      }
    else eri_assert_unreachable ();

  eri_assert_fclose (file);
  return 0;
}
