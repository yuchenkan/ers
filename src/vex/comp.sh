set -ex

rm -rf vex_data
LD_LIBRARY_PATH=. ../tracer --path=vex_data ./tst-vex raw
LD_LIBRARY_PATH=. /usr/bin/setarch x86_64 -R ./tst-vex
