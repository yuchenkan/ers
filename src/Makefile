all:
	gcc -I . -Wall -O3 -S -o lib/syscall-offsets.s lib/syscall-offsets.c
	grep __AS_DEFINE__ lib/syscall-offsets.s | sed 's/__AS_DEFINE__/#define/g' >lib/syscall-offsets.h
	\
	gcc -I . -Wall -O3 -S -o live-entry-offsets.s live-entry-offsets.c
	grep __AS_DEFINE__ live-entry-offsets.s | sed 's/__AS_DEFINE__/#define/g' >live-entry-offsets.h
	\
	gcc -I . -Wall -O3 -S -o public/entry-offsets.s public/entry-offsets.c
	grep __AS_DEFINE__ public/entry-offsets.s | sed 's/__AS_DEFINE__/#define/g' >public/entry-offsets.h
	\
	gcc -I . -Wall -O3 -S -o tst/tst-live-entry-offsets.s tst/tst-live-entry-offsets.c
	grep __AS_DEFINE__ tst/tst-live-entry-offsets.s | sed 's/__AS_DEFINE__/#define/g' >tst/tst-live-entry-offsets.h
	\
	gcc -I . -nostdlib -e tst_start tst/tst-live-entry.S lib/syscall.S lib/util.c lib/printf.c lib/lock.c lib/buf.c tst/tst-live-entry.c live-entry.c live-entry.S -o tst-live-entry -g -Wall
