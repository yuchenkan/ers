set -ex

for i in {1..200}
do
  echo $i
  rm -rf eri-live-log/
  rm -rf eri-replay-log/
  rm -rf eri-analysis-log/
  setarch `uname -m` -R "$@"
done
