set -ex

gcc -I . lib/tst/tst-atomic.c -o tst-atomic -g -O3
gcc -I . lib/tst/tst-list.c lib/util.c lib/lock.c lib/buf.c lib/printf.c -o tst-list -g -O3
gcc -I . lib/tst/tst-malloc.c lib/malloc.c lib/util.c lib/lock.c -o tst-malloc -g -O3
gcc -I . lib/tst/tst-printf.c lib/printf.c lib/malloc.c lib/util.c lib/lock.c lib/buf.c -o tst-printf -g -O3
gcc -I . lib/tst/tst-rbtree.c lib/printf.c lib/util.c lib/lock.c lib/buf.c -o tst-rbtree -g -O3
