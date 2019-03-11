#include <common.h>

#include <lib/malloc.h>
#include <lib/printf.h>

#include <replay/rtld.h>
#include <replay/thread.h>

struct thread_group
{
  struct eri_mtpool *pool;

  struct eri_common_args args;
};

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *rtld_args)
{
  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 1);
  struct thread_group *group
			= eri_assert_malloc (&pool->pool, sizeof *group);
  group->pool = pool;

  group->args.path = rtld_args->path;
  group->args.stack_size = rtld_args->stack_size;
  group->args.file_buf_size = rtld_args->file_buf_size;

  /* TODO */
  eri_assert_printf ("eri_replay_start\n");
  while (1) continue;
}
