set -ex
/usr/bin/setarch x86_64 -R ./replayer &
i=$!
sleep 1
cat /proc/$i/maps
kill $i
