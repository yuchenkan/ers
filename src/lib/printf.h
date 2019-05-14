#ifndef ERI_LIB_PRINTF_H
#define ERI_LIB_PRINTF_H

#ifndef ERI_APPLY_ERS
#include <lib/printf-specific.h>
#else

#include <tst/tst-printf-specific.h>

#define eri_fopen	tst_fopen
#define eri_fclose	tst_fclose
#define eri_assert_fopen	tst_assert_fopen
#define eri_assert_fclose	tst_assert_fclose
#define eri_fseek	tst_fseek
#define eri_assert_fseek	tst_assert_fseek
#define eri_fwrite	tst_fwrite
#define eri_fread	tst_fread
#define eri_assert_fwrite	tst_assert_fwrite
#define eri_assert_fread	tst_assert_fread
#define eri_vfprintf	tst_vfprintf
#define eri_fprintf	tst_fprintf
#define eri_vprintf	tst_vprintf
#define eri_printf	tst_printf
#define eri_assert_vfprintf	tst_assert_vfprintf
#define eri_assert_fprintf	tst_assert_fprintf
#define eri_assert_vprintf	tst_assert_vprintf
#define eri_assert_printf	tst_assert_printf
#define eri_lvfprintf	tst_lvfprintf
#define eri_lfprintf	tst_lfprintf
#define eri_lvprintf	tst_lvprintf
#define eri_lprintf	tst_lprintf
#define eri_assert_lvfprintf	tst_assert_lvfprintf
#define eri_assert_lfprintf	tst_assert_lfprintf
#define eri_assert_lvprintf	tst_assert_lvprintf
#define eri_assert_lprintf	tst_assert_lprintf
#define eri_file_foreach_line	tst_file_foreach_line
#define eri_assert_file_foreach_line	tst_assert_file_foreach_line

#endif

#endif
