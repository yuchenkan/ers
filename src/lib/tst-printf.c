#include "util.h"
#include "printf.h"

int main ()
{
  eri_assert (eri_printf ("") == 0);
  eri_assert (eri_printf ("%%\n") == 0);
  eri_assert (eri_printf ("%u%lx\n", 1, (unsigned long) 12345) == 0);
  eri_assert (eri_printf ("%u%s%x\n", 1, "test", 12345) == 0);
  eri_assert (eri_printf ("x%luy%s%sz%xa b c%%\n", (unsigned long) 1, "test", "", 12345) == 0);

  eri_file_t file;
  eri_assert (eri_fopen ("tst_printf.out", 0, &file, 0, 0) == 0);
  eri_assert (eri_fprintf (file, "test\n") == 0);
  eri_assert (eri_fprintf (file, "test%lx\n", 12345) == 0);
  eri_assert (eri_fwrite (file, "12345\n", 6, 0) == 0);
  eri_assert (eri_fclose (file) == 0);

  eri_assert (eri_fopen ("tst_printf.out", 0, &file, 0, 0) == 0);
  eri_assert (eri_fwrite (file, "12345\n", 6, 0) == 0);
  eri_assert (eri_fclose (file) == 0);

  char buf[4];
  size_t l;
  eri_assert (eri_fopen ("tst_printf.out", 1, &file, 0, 0) == 0);
  eri_assert (eri_fread (file, buf, 4, &l) == 0);
  eri_assert (l == 4 && buf[0] == '1' && buf[1] == '2' && buf[2] == '3' && buf[3] == '4');
  eri_assert (eri_fread (file, buf, 4, &l) == 0);
  eri_assert (l == 2 && buf[0] == '5' && buf[1] == '\n');
  eri_assert (eri_fclose (file) == 0);
  return 0;
}
