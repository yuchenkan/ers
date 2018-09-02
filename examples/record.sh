set -ex
SRC=${1:-threads}
rm -rf ers_data
time LD_PRELOAD=../src/librecorder.so ./$SRC-normal | tee record.log
