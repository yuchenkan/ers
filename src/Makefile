all:
	gcc -I . -Wall -O3 -S -o lib/syscall-offsets.s lib/syscall-offsets.c
	grep __AS_DEFINE__ lib/syscall-offsets.s | sed 's/__AS_DEFINE__/#define/g' >lib/syscall-offsets.h
	\
	gcc -I . -Wall -O3 -S -o live-offsets.s live-offsets.c
	grep __AS_DEFINE__ live-offsets.s | sed 's/__AS_DEFINE__/#define/g' >live-offsets.h
	\
	gcc -I . -Wall -O3 -S -o public/recorder-offsets.s public/recorder-offsets.c
	grep __AS_DEFINE__ public/recorder-offsets.s | sed 's/__AS_DEFINE__/#define/g' >public/recorder-offsets.h
	\
	gcc -I . -nostdlib -e main tst/tst-live-entry.S lib/syscall.S lib/util.c lib/printf.c lib/lock.c lib/buf.c tst/tst-live-entry.c recorder.c live.S -o tst-live-entry -g -Wall
