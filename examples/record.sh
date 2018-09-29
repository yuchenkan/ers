set -ex
SRC=${1:-threads}
rm -rf ers_data
LD_BIND_NOW=1 ./$SRC-normal
