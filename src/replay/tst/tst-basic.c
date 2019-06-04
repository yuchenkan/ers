#include <lib/elf.h>
#include <lib/compiler.h>
#include <lib/syscall.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/serial.h>

#include <replay/rtld.h>
#include <replay/thread.h>

#include <tst/tst-syscall.h>

static uint8_t stack[2 * 1024 * 1024];

static eri_noreturn void
tst_replay_start (void)
{
  eri_info ("start\n");
  tst_assert_sys_exit (0);
}

eri_noreturn void
tst_main (void **args)
{
  char *path = "ers-data";

  char **envp;
  for (envp = eri_get_envp_from_args (args); *envp; ++envp)
    eri_get_arg_str (*envp, "ERS_DATA=", &path);

  eri_mkdir (path);

  char name[eri_build_path_len (path, "t", 0)];
  eri_build_path (path, "t", 0, name);

  eri_file_t file;
  if (eri_fopen (name, 0, &file, 0, 0))
    {
      eri_assert_fprintf (ERI_STDERR, "failed to open data: %s\n", name);
      eri_assert_syscall (exit, 1);
    }

  eri_serialize_mark (file, ERI_INIT_RECORD);

  extern uint8_t tst_main_map_start[];
  extern uint8_t tst_main_map_end[];
  struct eri_init_record init_rec = {
    0, 0, (uint64_t) tst_stack_top (stack), (uint64_t) tst_replay_start,
    .map_range = {
      (uint64_t) tst_main_map_start, (uint64_t) tst_main_map_end
    },
    .atomic_table_size = 1
  };

  eri_serialize_init_record (file, &init_rec);
  eri_serialize_mark (file, ERI_SYNC_RECORD);
  eri_serialize_magic (file, ERI_SYSCALL_OUT_MAGIC);
  eri_serialize_uint64 (file, 0);

  eri_assert_fclose (file);

  extern uint8_t tst_main_buf_start[];
  extern uint8_t tst_main_buf_end[];
  struct eri_replay_rtld_args rtld_args = {
    init_rec.map_range, 4096, eri_global_enable_debug, path, 0, 0,
    .stack_size = 8 * 1024 * 1024,
    .file_buf_size = 64 * 1024, .buf = (uint64_t) tst_main_buf_start,
    .buf_size = tst_main_buf_end - tst_main_buf_start
  };
  eri_replay_start (&rtld_args);
}
