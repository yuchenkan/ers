set -ex

#gcc -I.. -g -fPIC -nostdlib -shared -Wl,--no-undefined vex.c -o libvex.so
#gcc -I ../../3rd/xed/include/public -I .. -g -Wall tst-vex.c vex.c ../lib/malloc.c ../lib/util.c ../../3rd/xed/obj/libxed.a -Wl,--exclude-libs,ALL -o tst-vex

gcc -I .. -S vex-offsets.c
grep '__AS_DEFINE__' vex-offsets.s | sed 's/#//g' | sed 's/__AS_DEFINE__/#define/g' >vex-offsets.h

gcc -I .. -I ../../3rd/xed/include/public -I ../../3rd/xed/include/public/xed -I ../../3rd/xed/obj -g -Wall -fPIC -nostdlib -shared -fvisibility=hidden tst-vex.c vex.c ../common.c ../lib/malloc.c ../lib/lock.c ../lib/util.c ../lib/printf.c ../../3rd/xed/obj/libxed.a -Wl,--exclude-libs,ALL -Wl,--no-undefined -o libtst-vex.so -fno-tree-loop-distribute-patterns -save-temps

objdump -dSl libtst-vex.so >libtst-vex.asm

gcc -g main.c -o main -ltst-vex -L.
