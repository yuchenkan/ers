set -ex

./tst-rtld
./tst-live-entry-start
./tst-live-entry-clone
./tst-live-entry

./tst-atomic
./tst-list
./tst-malloc
./tst-printf
./tst-rbtree
