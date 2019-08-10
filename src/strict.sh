set -ex

for i in {1..500}
do
  echo $i
  node ../make/make.js -j 64 . ../build/src all -p tst/goal/out.g >../build/strict.log
done
