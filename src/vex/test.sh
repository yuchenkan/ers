set -ex

rm -rf vex_data
LD_LIBRARY_PATH=. ${1:-/usr/bin/setarch x86_64 -R} ./tst
