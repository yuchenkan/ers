#include "common.h"
#include "lib/printf.h"

static void
proc_map_entry (const struct eri_map_entry *e, void *d)
{
  eri_assert (d == 0);
  eri_assert (eri_printf ("%lx %lx %u %s\n", e->start, e->end, e->perms, e->path ? : "") == 0);
}

int
main (void)
{
  eri_dump_maps (ERI_STDOUT);
  eri_process_maps (proc_map_entry, 0);
  return 0;
}
