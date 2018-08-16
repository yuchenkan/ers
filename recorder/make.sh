set -ex

# O=-O3
gcc $O -g -fPIC -Wall -nostdlib -Wl,--no-undefined common.c recorder.c lib/printf.c lib/malloc.c lib/util.c -shared -fvisibility=hidden -o librecorder.so -fno-tree-loop-distribute-patterns # -save-temps
gcc $O -g -Wall -nostdlib replayer.c common.c lib/util.c lib/printf.c -o replayer -fno-tree-loop-distribute-patterns

objdump -dSl librecorder.so >librecorder.s
