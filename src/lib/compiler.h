#ifndef ERI_LIB_COMPILER_H
#define ERI_LIB_COMPILER_H

#define eri_noreturn	__attribute__ ((noreturn))
#define eri_returns_twice	__attribute__ ((returns_twice))
#define eri_aligned16	__attribute__ ((aligned (16)))
#define eri_unused	__attribute__ ((unused))
#define eri_packed	__attribute__ ((packed))

#endif
