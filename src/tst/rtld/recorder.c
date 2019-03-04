#include <rtld.h>
#include <lib/printf.h>

void
start (struct eri_rtld_args *rtld)
{
  eri_assert_printf ("start: %lx %lx %lx %lx\n",
		     rtld->rsp, rtld->rip,
		     rtld->map_start, rtld->map_end);
}
