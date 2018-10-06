set -x

bash record.sh "$@"
bash replay.sh --analysis
