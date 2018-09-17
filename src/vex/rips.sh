set -ex

bash main.sh 2>main.err | tee main.out | grep '>>>>' >main.rips
LD_LIBRARY_PATH=. ./tracer | tee tracer.rips
