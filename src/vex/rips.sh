set -ex

bash test.sh 2>test.err | tee test.out | grep '>>>>' >test.rips
LD_LIBRARY_PATH=. ./tracer | tee tracer.rips
