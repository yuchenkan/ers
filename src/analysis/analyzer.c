#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/malloc.h>

#include <common/thread.h>

#include <analysis/analyzer.h>

struct eri_analyzer_group *
eri_analyzer_group__create (struct eri_mtpool *pool)
{
  return 0;
}

void
eri_analyzer_group__destroy (struct eri_analyzer_group *group)
{
}

struct eri_analyzer *
eri_analyzer__create (struct eri_analyzer_group *group)
{
  return 0;
}

void
eri_analyzer__destroy (struct eri_analyzer *analyzer)
{
}

eri_noreturn void
eri_analyzer__enter (struct eri_analyzer *analyzer,
		     struct eri_registers *regs)
{
  eri_assert_unreachable ();
}
