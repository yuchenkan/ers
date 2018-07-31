set -ex

gcc -v -g -fPIC -Wall -nostdlib -Wl,--no-undefined recorder.c lib/printf.c lib/malloc.c lib/util.c lib/lock.c -shared -fvisibility=hidden -o librecorder.so
