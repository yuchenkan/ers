set -ex
SRC=${1:-threads}
rm -rf ers_data
./$SRC-normal
