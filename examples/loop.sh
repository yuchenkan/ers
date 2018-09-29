set -ex

for i in {1..50}
do
  echo $i
  bash -e test.sh "$@"
done
