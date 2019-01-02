#include <stdint.h>

#include "lib/util.h"
#include "lib/printf.h"
#include "lib/buf.h"
#include "lib/malloc.h"

static void
proc_line (const char *ln, uint64_t sz, void *d)
{
  eri_assert (d == 0);
  ((char *) ln)[sz] = '\0';
  eri_assert_printf ("%s ...%lu\n", ln, sz);
}

static uint8_t pool_buf[1024 * 1024];

static void
tst_foreach_line (uint64_t size)
{
  struct eri_pool pool;
  eri_assert_init_pool (&pool, pool_buf, sizeof pool_buf);
  struct eri_buf buf;
  eri_assert (eri_buf_pool_init (&buf, &pool, size) == 0);
  eri_assert (eri_file_foreach_line ("/proc/self/smaps",
				     &buf, proc_line, 0) == 0);
  eri_assert (eri_buf_fini (&buf) == 0);
  eri_assert_fini_pool (&pool);
}

int32_t
main (void)
{
  eri_assert_printf ("");
  eri_assert_printf ("%%\n");
  eri_assert_printf ("%u%lx\n", 1, (unsigned long) 12345);
  eri_assert_printf ("%u%s%x\n", 1, "test", 12345);
  eri_assert_printf ("x%luy%s%sz%xa b c%%\n",
		     (unsigned long) 1, "test", "", 12345);

  eri_file_t file;
  eri_assert_fopen ("tst-printf.txt", 0, &file, 0, 0);
  eri_assert_fprintf (file, "test\n");
  eri_assert_fprintf (file, "test%lx\n", 12345);
  eri_assert_fwrite (file, "12345\n", 6, 0);
  eri_assert_fclose (file) ;

  eri_assert_fopen ("tst-printf.txt", 0, &file, 0, 0);
  eri_assert_fwrite (file, "12345\n", 6, 0);
  eri_assert_fclose (file);

  char buf[4];
  uint64_t l;
  eri_assert_fopen ("tst-printf.txt", 1, &file, 0, 0);
  eri_assert_fread (file, buf, 4, &l);
  eri_assert (l == 4 && buf[0] == '1'
	      && buf[1] == '2' && buf[2] == '3' && buf[3] == '4');
  eri_assert_fread (file, buf, 4, &l);
  eri_assert (l == 2 && buf[0] == '5' && buf[1] == '\n');
  eri_assert_fclose (file);

  tst_foreach_line (1024);
  tst_foreach_line (32);
  return 0;
}
