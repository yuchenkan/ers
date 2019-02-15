#include <rtld.h>
#include <lib/printf.h>

void
tst_rtld (struct eri_rtld_args *rtld)
{
  eri_assert_printf ("tst_rtld: %lx %lx %lx %lx\n",
		     rtld->rsp, rtld->rip,
		     rtld->map_start, rtld->map_end);
}
