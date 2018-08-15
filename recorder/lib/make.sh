set -ex

gcc -g -Wall util.c lock.c malloc.c tst-malloc.c -o tst-malloc
gcc -g -Wall printf.c util.c tst-printf.c -o tst-printf
gcc -g -Wall tst-list.c util.c printf.c -o tst-list
gcc -g -Wall tst-rbtree.c util.c printf.c -o tst-rbtree # -save-temps
