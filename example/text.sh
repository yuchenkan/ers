set -e

SRC=${1:-threads}

function add_symbol_file ()
{
  f=$1
  b=0x$(grep $f ers_data/maps-log | grep 'r-xp' | awk '{ print $1 }' | cut -f1 -d-)
  o=0x$(objdump -h $f | grep .text | awk '{ print $6 }')
  s=0x$(printf '%x' $((b + o)))
  echo add-symbol-file $f $s
}

add_symbol_file /work/demo/example/$SRC-normal
add_symbol_file /work/glibc-obj/nptl/libpthread.so
add_symbol_file /work/glibc-obj/libc.so
add_symbol_file /work/glibc-obj/elf/ld.so
add_symbol_file /work/demo/recorder/librecorder.so
