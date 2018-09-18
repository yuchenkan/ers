set -ex

#gcc -I.. -g -fPIC -nostdlib -shared -Wl,--no-undefined vex.c -o libvex.so
#gcc -I ../../3rd/xed/include/public -I .. -g -Wall tst-vex.c vex.c ../lib/malloc.c ../lib/util.c ../../3rd/xed/obj/libxed.a -Wl,--exclude-libs,ALL -o tst-vex

gcc -I .. -S vex-offsets.c -o vex-offsets.s
grep '__AS_DEFINE__' vex-offsets.s | sed 's/__AS_DEFINE__/#define/g' >vex-offsets.h

gcc -I .. -I ../../3rd/xed/include/public -I ../../3rd/xed/include/public/xed -I ../../3rd/xed/obj -g -Wall -fPIC -nostdlib -shared -fvisibility=hidden tst-vex.c vex.c ../common.c ../lib/malloc.c ../lib/lock.c ../lib/util.c ../lib/printf.c ../../3rd/xed/obj/libxed.a -Wl,--exclude-libs,ALL -Wl,--no-undefined -o libtst-vex.so -fno-tree-loop-distribute-patterns -save-temps -mgeneral-regs-only

objdump -dSl libtst-vex.so >libtst-vex.asm

gcc -g tst.c -o tst -ltst-vex -L. -nostdlib

# glibc pieces:
BUILD=/work/glibc-obj
DYNLINKER=--dynamic-linker="${BUILD}"/elf/ld.so
LINKPATH=-rpath="${BUILD}":"${BUILD}"/math:"${BUILD}"/elf:"${BUILD}"/dlfcn:"${BUILD}"/nss:"${BUILD}"/nis:"${BUILD}"/rt:"${BUILD}"/resolv:"${BUILD}"/crypt:"${BUILD}"/mathvec:"${BUILD}"/nptl
CRT1="${BUILD}"/csu/crt1.o
CRT1_PIE="${BUILD}"/csu/Scrt1.o
CRTI="${BUILD}"/csu/crti.o
CRTN="${BUILD}"/csu/crtn.o

# gcc pieces:
CRTBEGIN_STATIC=$(gcc -print-file-name="crtbeginT.o")
CRTBEGIN_PIE=$(gcc -print-file-name="crtbeginS.o")
CRTBEGIN_NORMAL=$(gcc -print-file-name="crtbegin.o")
CRTEND=$(gcc -print-file-name="crtend.o")
CRTEND_PIE=$(gcc -print-file-name="crtendS.o")
GCCINSTALL=$(gcc -print-search-dirs | grep 'install:' | sed -e 's,^install: ,,g')
LD=$(gcc -print-prog-name="collect2")

# Application pieces:
PROG_NAME_NORMAL=main
PROG_SOURCE=main.c
PROG_OBJ=main.o
MAP_NORMAL=mapfile-normal.txt
CFLAGS="-g3 -O0"

# Compile the application.
rm -f $PROG_NAME_NORMAL
rm -f $PROG_OBJ
rm -f $MAP_NORMAL

# Once for static and normal builds and once for shared (PIE).
# These compilations still use the old C library headers.
gcc $CFLAGS -c $PROG_SOURCE -o $PROG_OBJ

# Link it against a hybrid combination of:
# - Newly build glibc.
# - Split out libpthread because the .so is a linker script.
# - C development environment present on the system.
# Notes:
# - LTO is not supported.
# - Profiling is not supported (-pg).
# - Only works for gcc.
# - Only works for x86_64.
# - Assumes we are using only the first and default multlib.

# Normal build:
$LD --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 \
$DYNLINKER $LINKPATH  -o \
$PROG_NAME_NORMAL $CRT1 $CRTI $CRTBEGIN_NORMAL \
-L$GCCINSTALL \
-L$GCCINSTALL/../../../../lib64 \
-L/lib/../lib64 \
-L/usr/lib/../lib64 \
-L$GCCINSTALL/../../.. \
-Map $MAP_NORMAL \
$PROG_OBJ \
-lgcc --as-needed -lgcc_s --no-as-needed \
${BUILD}/libc.so.6 ${BUILD}/libc_nonshared.a --as-needed ${BUILD}/elf/ld.so --no-as-needed \
-lgcc --as-needed -lgcc_s --no-as-needed \
$CRTEND $CRTN \
 -ltst-vex -L.

objdump -dSl main >main.asm

gcc -I .. -O3 tracer.c -o tracer
