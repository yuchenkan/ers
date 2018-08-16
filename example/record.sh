set -ex
rm -rf ers_data
LD_PRELOAD=../recorder/librecorder.so ./threads-normal | tee record.log
