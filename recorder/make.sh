set -ex

gcc -v --sysroot=/work/glibc-local -idirafter /usr/include/ -g -fPIC -Wall recorder.c ../common/common.c -shared -o librecorder.so
