set -ex

rm -rf vex_data
bash main.sh
LD_LIBRARY_PATH=. ../tracer --path=vex_data ./tst-vex raw
