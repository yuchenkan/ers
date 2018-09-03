set -ex

for i in {1..50}
do
  bash test.sh "$@"
done
