set -ex

rm -rf vex_data
LD_LIBRARY_PATH=. ${1:-/usr/bin/setarch x86_64 -R} ./main
#objdump -D -b binary -mi386:x86-64 -Mintel ./trans
#objdump -D -b binary -mi386:x86-64 ./trans
