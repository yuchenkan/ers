set -ex

SYSROOT=/work/glibc-local
gcc \
  -L${SYSROOT}/usr/lib64 \
  -I${SYSROOT}/include \
  --sysroot=${SYSROOT} \
  -Wl,-rpath=${SYSROOT}/lib64 \
  -Wl,--dynamic-linker=${SYSROOT}/lib64/ld-2.27.so \
  -Wl,-Map,linker.map \
  -lpthread -o threads threads.c
