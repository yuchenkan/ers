set -ex

./tst-rtld
./tst-live-entry-start
./tst-live-entry-clone
./tst-live-entry-sig-ignore
./tst-live-entry

./tst-live-quit
./tst-live-quit-clone
./tst-live-quit-join
./tst-live-quit-ctid-segv
./tst-live-quit-group

./tst-atomic
./tst-list
./tst-malloc
./tst-printf
./tst-rbtree
