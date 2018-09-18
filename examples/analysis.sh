set -x

bash record.sh "$@"
bash replay.sh --analysis

for f in ers_data/record-log-*
do
  id=$(echo -n $f | cut -f3 -d-)
  diff $f ers_data/replay-log-$id
done
