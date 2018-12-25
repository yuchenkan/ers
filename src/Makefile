all:
	gcc -I . -Wall -O3 -S -o rtld-offsets.s rtld-offsets.c
	grep __AS_DEFINE__ rtld-offsets.s | sed 's/__AS_DEFINE__/#define/g' >rtld-offsets.h
	\
	gcc -I . -Wall -O3 -S -o lib/syscall-offsets.s lib/syscall-offsets.c
	grep __AS_DEFINE__ lib/syscall-offsets.s | sed 's/__AS_DEFINE__/#define/g' >lib/syscall-offsets.h
	\
	gcc -I . -Wall -O3 -S -o live-entry-offsets.s live-entry-offsets.c
	grep __AS_DEFINE__ live-entry-offsets.s | sed 's/__AS_DEFINE__/#define/g' >live-entry-offsets.h
	\
	gcc -I . -Wall -O3 -S -o public/entry-offsets.s public/entry-offsets.c
	grep __AS_DEFINE__ public/entry-offsets.s | sed 's/__AS_DEFINE__/#define/g' >public/entry-offsets.h
	\
	gcc -I . -Wall -O3 -S -o tst/tst-live-entry-common-offsets.s tst/tst-live-entry-common-offsets.c
	grep __AS_DEFINE__ tst/tst-live-entry-common-offsets.s | sed 's/__AS_DEFINE__/#define/g' >tst/tst-live-entry-common-offsets.h
	\
	gcc -I . -Wall -O3 -fno-tree-loop-distribute-patterns -nostdlib -Wl,-e,tst_start -Wl,--no-undefined -g tst/tst-common-start.S tst/tst-live-quit-clone.c tst/tst-live-quit-common.c tst/tst-live-quit-common.S live.c live.S common.S common.c lib/malloc.c lib/loop.c lib/syscall.S lib/util.c lib/printf.c lib/lock.c lib/buf.c -o tst-live-quit-clone -D TST_LIVE_QUIT_CLONE
	\
	gcc -I . -Wall -O3 -fno-tree-loop-distribute-patterns -nostdlib -Wl,-e,tst_start -Wl,--no-undefined -g tst/tst-common-start.S tst/tst-live-quit.c tst/tst-live-quit-common.c tst/tst-live-quit-common.S live.c live.S common.S common.c lib/malloc.c lib/loop.c lib/syscall.S lib/util.c lib/printf.c lib/lock.c lib/buf.c -o tst-live-quit
	\
	gcc -I . -nostdlib -Wl,-e,tst_start tst/tst-common-start.S tst/tst-util.c tst/tst-live-entry-common.S tst/tst-live-entry-common.c tst/tst-live-entry.S lib/syscall.S lib/util.c lib/printf.c lib/lock.c lib/buf.c tst/tst-live-entry.c live-entry.c live-entry.S -o tst-live-entry -g -Wall -Wl,--no-undefined -O3 -fno-tree-loop-distribute-patterns
	\
	gcc -I . -nostdlib -Wl,-e,tst_start tst/tst-live-entry-start.S lib/syscall.S lib/util.c lib/printf.c lib/lock.c lib/buf.c tst/tst-live-entry-start.c tst/tst-util.c tst/tst-live-entry-common.c live-entry.c live-entry.S -o tst-live-entry-start -g -Wall -Wl,--no-undefined -O3 -fno-tree-loop-distribute-patterns
	\
	gcc -I . -nostdlib -Wl,-e,tst_start tst/tst-common-start.S tst/tst-util.c tst/tst-live-entry-common.S tst/tst-live-entry-common.c lib/syscall.S lib/util.c lib/printf.c lib/lock.c lib/buf.c tst/tst-live-entry-clone.S tst/tst-live-entry-clone.c live-entry.c live-entry.S -o tst-live-entry-clone -g -Wall -Wl,--no-undefined -O3 -fno-tree-loop-distribute-patterns
	\
	bash make.sh
	\
	bash lib/tst/make.sh
