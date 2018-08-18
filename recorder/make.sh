set -ex

O=-O3
gcc $O -g -fPIC -Wall -nostdlib -Wl,--no-undefined common.c recorder.c lib/printf.c lib/malloc.c lib/util.c -shared -fvisibility=hidden -o librecorder.so -fno-tree-loop-distribute-patterns -save-temps
gcc $O -g -Wall -nostdlib replayer.c common.c lib/util.c lib/printf.c -o replayer -fno-tree-loop-distribute-patterns

objdump -dSl librecorder.so >librecorder.asm
objdump -dSl replayer >replayer.asm

gcc $O -g -Wall tst-asm.c -L . -lrecorder -o tst-asm -save-temps
objdump -W tst-asm >tst-asm.dwarf
objdump -dSl tst-asm >tst-asm.asm
