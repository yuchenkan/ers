set -ex

rm -rf vex_data
LD_LIBRARY_PATH=. valgrind --smc-check=all --track-origins=yes -vgdb-error=0 ./tst-vex
