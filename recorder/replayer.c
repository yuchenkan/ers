#include "common.h"

#include "lib/util.h"
#include "lib/rbtree.h"
#include "lib/printf.h"
#include "lib/syscall.h"

asm ("  .text\n\
  .global _start\n\
_start:\n\
  movq %rsp, %rdi\n\
  call start\n\
.previous\n"
);

struct proc_map_data
{
  unsigned long vdso_start, vdso_end;
  unsigned long vvar_start, vvar_end;
  unsigned long vsyscall_start, vsyscall_end;
  unsigned long stack_start, stack_end;
  unsigned long start, end;
  char num;
};

static void
proc_map_entry (const struct eri_map_entry *ent, void *data)
{
  eri_assert (ent->path);
  struct proc_map_data *d = data;
  ++d->num;
  if (eri_strcmp (ent->path, "[vdso]") == 0)
    {
      d->vdso_start = ent->start;
      d->vdso_end = ent->end;
    }
  else if (eri_strcmp (ent->path, "[vvar]") == 0)
    {
      d->vvar_start = ent->start;
      d->vvar_end = ent->end;
    }
  else if (eri_strcmp (ent->path, "[vsyscall]") == 0)
    {
      d->vsyscall_start = ent->start;
      d->vsyscall_end = ent->end;
    }
  else if (eri_strcmp (ent->path, "[stack]") == 0)
    {
      d->stack_start = ent->start;
      d->stack_end = ent->end;
    }
  else
    {
      d->start = ent->start;
      d->end = ent->end;
    }
}

asm ("  .text\n\
  .type  restore, @function\n\
restore:\n\
  movq  %rdi, %r15\n\
  movq  (%r15), %r12		/* init */\n\
\n\
  movq  8(%r15), %rdi		/* stack_start */\n\
  movq  16(%r15), %rsi		/* stack_end - stack_start */\n\
  movl  $"ERI_STRINGIFY (__NR_munmap)", %eax\n\
  syscall\n\
  cmpq  $-4095, %rax\n\
  jae  .error\n\
\n\
  movq  24(%r15), %rdi		/* start */\n\
  movq  32(%r15), %rsi		/* end - start */\n\
  movl  $"ERI_STRINGIFY (__NR_munmap)", %eax\n\
  syscall\n\
  cmpq  $-4095, %rax\n\
  jae  .error\n\
\n\
  movq  40(%r15), %r13		/* size */\n\
  addq  $48, %r15\n\
.map:\n\
  testq  %r13, %r13\n\
  jz  .mapped\n\
\n\
  movq  (%r15), %rdi		/* map_start */\n\
  movq  8(%r15), %rsi		/* map_end - map_start */\n\
  movq  16(%r15), %rdx\n\
  andq  $7, %rdx		/* map_prot */\n\
  orq  $"ERI_STRINGIFY (ERI_PROT_WRITE)", %rdx	/* map_prot | write */\n\
  movq  24(%r15), %r10		/* map_flags */\n\
  movq  $-1, %r8\n\
  xorq  %r9, %r9\n\
  movl  $"ERI_STRINGIFY (__NR_mmap)", %eax\n\
  syscall\n\
  cmpq  $-4095, %rax\n\
  jae  .error\n\
\n\
  movq  16(%r15), %rax		/* flags */\n\
  andq  $"ERI_STRINGIFY (ERI_PROT_READ)", %rax\n\
  jz  .write_done		/* not readable */\n\
  movq  16(%r15), %rax		/* flags */\n\
  andq  $8, %rax\n\
  jnz  .write_done		/* all zero */\n\
\n\
  movq  %r12, %rdi		/* init */\n\
  movq  32(%r15), %rsi		/* offset */\n\
  movq  $0, %rdx		/* SEEK_SET */\n\
  movl  $"ERI_STRINGIFY (__NR_lseek)", %eax\n\
  syscall\n\
  cmpq  $-4095, %rax\n\
  jae  .error\n\
  xorq  %r14, %r14		/* count */\n\
.write:\n\
  movq  (%r15), %rsi\n\
  addq  %r14, %rsi		/* buf */\n\
  movq  8(%r15), %rdx\n\
  subq  %r14, %rdx		/* count */\n\
  movl  $"ERI_STRINGIFY (__NR_read)", %eax\n\
  syscall\n\
  cmpq  $-4095, %rax\n\
  jae  .error\n\
  testq  %rax, %rax\n\
  jz  .error			/* eof */\n\
  addq  %rax, %r14\n\
  cmpq  8(%r15), %r14\n\
  jne  .write\n\
\n\
.write_done:\n\
  movq  16(%r15), %rax		/* flags */\n\
  movq  %rax, %rbx\n\
  orq  $"ERI_STRINGIFY (ERI_PROT_WRITE)", %rbx\n\
  cmpq  %rax, %rbx\n\
  je  .map_next\n\
\n\
  movq  (%r15), %rdi		/* map_start */\n\
  movq  8(%r15), %rsi		/* map_end - map_start */\n\
  movq  16(%r15), %rdx\n\
  andq  $7, %rdx		/* map_prot */\n\
  movl  $"ERI_STRINGIFY (__NR_mprotect)", %eax\n\
  syscall\n\
  cmpq  $-4095, %rax\n\
  jae  .error\n\
.map_next:\n\
  addq  $40, %r15\n\
  subq  $1, %r13\n\
  jmp  .map\n\
\n\
.mapped:\n\
  leaq  112(%r15), %rcx\n\
  fldenv  (%rcx)\n\
  ldmxcsr  136(%r15)\n\
\n\
  movq  104(%r15), %rsp\n\
  movq  (%r15), %rbx\n\
  movq  8(%r15), %rbp\n\
  movq  16(%r15), %r12\n\
  movq  24(%r15), %r13\n\
  movq  32(%r15), %r14\n\
\n\
  movq  96(%r15), %rcx\n\
  pushq  %rcx			/* rip */\n\
\n\
  movq  48(%r15), %rdi\n\
  movq  56(%r15), %rsi\n\
  movq  64(%r15), %rdx\n\
  movq  72(%r15), %rcx\n\
  movq  80(%r15), %r8\n\
  movq  88(%r15), %r9\n\
\n\
  movq  144(%r15), %rax\n\
  movq  %rax, 144(%rdi)		/* unmap_start */\n\
  movq  152(%r15), %rax\n\
  movq  %rax, 152(%rdi)		/* unmap_size */\n\
\n\
  movq  40(%r15), %r15\n\
  jmp  .return\n\
\n\
.error:\n\
  movq  $0, %rax\n\
  movq  $1, (%rax)\n\
\n\
.return:\n\
  movb  $1, %al\n\
  ret\n\
  .size  restore, .-restore\n\
restore_end:\n"
);

/* static */ void restore (unsigned long addr);

struct map
{
  unsigned long start;
  unsigned long end;
  char flags;
  unsigned long offset;
  ERI_RBT_NODE_FIELDS (map, struct map)
};

struct maps
{
  ERI_RBT_TREE_FIELDS (map, struct map)
};

ERI_DEFINE_RBTREE (static, map, struct maps, struct map, unsigned long, eri_less_than)

static char
overlap (unsigned long a, unsigned long b, unsigned long c, unsigned long d)
{
  return b > c && a < d;
}

static void
start (void **arg)
{
  unsigned long  argc = *(unsigned long *) arg;
  const char **argv = (const char **) (arg + 1);

  const char *path = argc == 1 ? "ers_data" : argv[1];

  struct proc_map_data pd;
  eri_memset (&pd, 0, sizeof pd);
  eri_process_maps (proc_map_entry, &pd);
  eri_assert (pd.num == 5);

  ERI_ASSERT_SYSCALL (munmap, pd.vdso_start, pd.vdso_end - pd.vdso_start);
  ERI_ASSERT_SYSCALL (munmap, pd.vvar_start, pd.vvar_end - pd.vvar_start);

  eri_assert (eri_printf ("\n") == 0);
  eri_dump_maps ();

  struct maps maps;
  ERI_RBT_INIT_TREE (map, &maps);

  int init = eri_open_path (path, "init", ERI_OPEN_REPLAY, 0);
  char mk;
  while ((mk = eri_load_mark (init)) == ERI_MARK_INIT_MAP)
    {
      struct map *map = __builtin_alloca (sizeof *map);
      eri_load_init_map (init, &map->start, &map->end, &map->flags);
      eri_assert (eri_printf ("%lx-%lx, %u\n", map->start, map->end, map->flags) == 0);
      map->offset = ERI_ASSERT_SYSCALL_RES (lseek, init, 0, ERI_SEEK_CUR);
      if (map->flags & 1 && ! (map->flags & 8))
	eri_skip_init_map_data (init, map->end - map->start);
      map_insert (&maps, map);
    }
  eri_assert (mk == ERI_MARK_INIT_CONTEXT);
  struct eri_context ctx;
  eri_load_init_context (init, &ctx);
  eri_assert (eri_load_mark (init) == ERI_MARK_NONE);

  size_t data_size = eri_round_up (
	6 * sizeof (unsigned long) /* init, stack[2], text[2], map_size */
	+ map_get_size (&maps) * sizeof (unsigned long) * 5 /* map_size * (start, size, prot, flags, offset) */
	+ eri_round_up (sizeof ctx.env, sizeof (unsigned long))
	+ 2 * sizeof (unsigned long), /* unmap */
	4096);
  extern const char restore_end[];
  size_t size = data_size + eri_round_up (restore_end - (char *) restore, 4096);
  eri_assert (eri_printf ("size %lu\n", size) == 0);

  unsigned long addr = 0;
  struct map *m;
  ERI_RBT_FOREACH (map, &maps, m)
    {
      while (m->start - addr >= size)
	{
	  if (! overlap (addr, addr + size, pd.vsyscall_start, pd.vsyscall_end)
	      && ! overlap (addr, addr + size, pd.stack_start, pd.stack_end)
	      && ! overlap (addr, addr + size, pd.start, pd.end)
	      && ! ERI_SYSCALL_ERROR_P (ERI_SYSCALL (
			mmap, addr, size, ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS | ERI_MAP_FIXED, -1, 0)))
	    goto mapped;
	  addr += size;
	}
      addr = m->end;
    }
mapped:
  eri_assert (eri_printf ("addr %lx\n", addr) == 0);

  char *data = (char *) addr;
  *(long *) data = init;
  *(unsigned long *) (data += sizeof (unsigned long)) = pd.stack_start;
  *(unsigned long *) (data += sizeof (unsigned long)) = pd.stack_end - pd.stack_start;
  *(unsigned long *) (data += sizeof (unsigned long)) = pd.start;
  *(unsigned long *) (data += sizeof (unsigned long)) = pd.end - pd.start;
  *(size_t *) (data += sizeof (unsigned long)) = map_get_size (&maps);
  ERI_RBT_FOREACH (map, &maps, m)
    {
      *(unsigned long *) (data += sizeof (unsigned long)) = m->start;
      *(unsigned long *) (data += sizeof (unsigned long)) = m->end - m->start;
      *(unsigned long *) (data += sizeof (unsigned long)) = m->flags & 15;
      int flags = ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS | ERI_MAP_FIXED;
      if (m->flags & 16) flags |= ERI_MAP_GROWSDOWN;
      *(unsigned long *) (data += sizeof (unsigned long)) = flags;
      *(unsigned long *) (data += sizeof (unsigned long)) = m->offset;
    }
  eri_memcpy (data += sizeof (unsigned long), &ctx.env, sizeof ctx.env);
  *(unsigned long *) (data += eri_round_up (sizeof ctx.env, sizeof (unsigned long))) = addr;
  *(unsigned long *) (data += sizeof (unsigned long)) = size;

  struct map *nm;
  ERI_RBT_FOREACH_SAFE (map, &maps, m, nm) map_remove (&maps, m);

  char *code = (char *) addr + data_size;
  eri_memcpy (code, restore, restore_end - (char *) restore);

  ((typeof (&restore)) code) (addr);
}
