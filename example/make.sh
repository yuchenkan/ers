set -ex

# glibc pieces:
BUILD=/work/glibc-obj
SYSROOT=/work/glibc-local
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
PROG_NAME_STATIC=threads-static
PROG_NAME_NORMAL=threads-normal
PROG_NAME_PIE=threads-pie
PROG_SOURCE=threads.c
PROG_OBJ=threads.o
PROG_OBJ_PIE=threads.os
MAP_STATIC=mapfile-static.txt
MAP_NORMAL=mapfile-normal.txt
MAP_PIE=mapfile-pie.txt
CFLAGS="-g3 -O0"

# Compile the application.
rm -f $PROG_NAME_STATIC
rm -f $PROG_NAME_NORMAL
rm -f $PROG_NAME_PIE
rm -f $PROG_OBJ
rm -f $PROG_OBJ_PIE
rm -f $MAP_STATIC
rm -f $MAP_NORMAL
rm -f $MAP_PIE

# Once for static and normal builds and once for shared (PIE).
# These compilations still use the old C library headers.
gcc --sysroot=$SYSROOT $CFLAGS -c $PROG_SOURCE -o $PROG_OBJ
gcc --sysroot=$SYSROOT -pie -fPIC $CFLAGS -c $PROG_SOURCE -o $PROG_OBJ_PIE

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

# Static build:
$LD --build-id --no-add-needed --hash-style=gnu -m elf_x86_64 -static -o \
$PROG_NAME_STATIC $CRT1 $CRTI $CRTBEGIN_STATIC \
-L$GCCINSTALL \
-L$GCCINSTALL/../../../../lib64 \
-L/lib/../lib64 \
-L/usr/lib/../lib64 \
-L$GCCINSTALL/../../.. \
-Map $MAP_STATIC \
$PROG_OBJ \
$BUILD/nptl/libpthread.a \
--start-group -lgcc -lgcc_eh $BUILD/libc.a --end-group \
$CRTEND $CRTN

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
${BUILD}/nptl/libpthread.so.0 ${BUILD}/nptl/libpthread_nonshared.a \
-lgcc --as-needed -lgcc_s --no-as-needed \
${BUILD}/libc.so.6 ${BUILD}/libc_nonshared.a --as-needed ${BUILD}/elf/ld.so --no-as-needed \
-lgcc --as-needed -lgcc_s --no-as-needed \
$CRTEND $CRTN

# PIE build:
$LD --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 \
$DYNLINKER $LINKPATH -pie -o \
$PROG_NAME_PIE $CRT1_PIE $CRTI $CRTBEGIN_PIE \
-L$GCCINSTALL \
-L$GCCINSTALL/../../../../lib64 \
-L/lib/../lib64 \
-L/usr/lib/../lib64 \
-L$GCCINSTALL/../../.. \
-Map $MAP_PIE \
$PROG_OBJ_PIE \
${BUILD}/nptl/libpthread.so.0 ${BUILD}/nptl/libpthread_nonshared.a \
-lgcc --as-needed -lgcc_s --no-as-needed \
${BUILD}/libc.so.6 ${BUILD}/libc_nonshared.a --as-needed ${BUILD}/elf/ld.so --no-as-needed \
-lgcc --as-needed -lgcc_s --no-as-needed \
$CRTEND_PIE $CRTN
