#include "util.h"
#include "printf.h"

int main ()
{
  ers_assert (ers_printf ("") == 0);
  ers_assert (ers_printf ("%%\n") == 0);
  ers_assert (ers_printf ("%u%lx\n", 1, (unsigned long) 12345) == 0);
  ers_assert (ers_printf ("%u%s%x\n", 1, "test", 12345) == 0);
  ers_assert (ers_printf ("x%luy%s%sz%xa b c%%\n", (unsigned long) 1, "test", "", 12345) == 0);

  int fd;
  ers_assert (ers_fopen ("tst_printf.out", 0, &fd) == 0);
  ers_assert (ers_fprintf (fd, "test\n") == 0);
  ers_assert (ers_fprintf (fd, "test%lx\n", 12345) == 0);
  ers_assert (ers_fwrite (fd, "12345\n", 6) == 0);
  ers_assert (ers_fclose (fd) == 0);

  ers_assert (ers_fopen ("tst_printf.out", 0, &fd) == 0);
  ers_assert (ers_fwrite (fd, "12345\n", 6) == 0);
  ers_assert (ers_fclose (fd) == 0);

  char buf[4];
  int l;
  ers_assert (ers_fopen ("tst_printf.out", 1, &fd) == 0);
  ers_assert (ers_fread (fd, buf, 4, &l) == 0);
  ers_assert (l == 4 && buf[0] == '1' && buf[1] == '2' && buf[2] == '3' && buf[3] == '4');
  ers_assert (ers_fread (fd, buf, 4, &l) == 0);
  ers_assert (l == 2 && buf[0] == '5' && buf[1] == '\n');
  ers_assert (ers_fclose (fd) == 0);
  return 0;
}
