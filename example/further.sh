set -ex

for i in {1..50}
do
  rm ers_data/replay-*
  ../recorder/replayer

  for f in ers_data/record-log-*
  do
    id=$(echo -n $f | cut -f3 -d-)
    diff $f ers_data/replay-log-$id
  done
done
