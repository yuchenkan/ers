set -ex

for i in {1..200}
do
  echo $i
  setarch `uname -m` -R "$@"
done
