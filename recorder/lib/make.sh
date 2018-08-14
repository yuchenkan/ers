set -ex

gcc -g -Wall util.c lock.c malloc.c tst_malloc.c -o tst_malloc
gcc -g -Wall printf.c util.c tst_printf.c -o tst_printf
gcc -g -Wall tst_list.c util.c printf.c -o tst_list
gcc -g -Wall tst_rbtree.c util.c printf.c -o tst_rbtree # -save-temps
