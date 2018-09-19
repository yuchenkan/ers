set -ex

LD_LIBRARY_PATH=. ${1:-/usr/bin/setarch x86_64 -R} ${1/gdb/--args} ./tst-vex raw
