set -ex

for i in {1..50}
do
  setarch `uname -m` -R "$@"
done
