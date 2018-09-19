GLIBC_BUILD := /work/glibc-obj
GLIBC_SYSROOT := /work/glibc-local

GLIBC_DYNLINKER := --dynamic-linker=$(GLIBC_BUILD)/elf/ld.so
GLIBC_LINKPATH := -rpath=$(GLIBC_BUILD):$(GLIBC_BUILD)/math:$(GLIBC_BUILD)/elf:$(GLIBC_BUILD)/dlfcn:$(GLIBC_BUILD)/nss:$(GLIBC_BUILD)/nis:$(GLIBC_BUILD)/rt:$(GLIBC_BUILD)/resolv:$(GLIBC_BUILD)/crypt:$(GLIBC_BUILD)/mathvec:$(GLIBC_BUILD)/nptl

GLIBC_CRT1 := $(GLIBC_BUILD)/csu/crt1.o
GLIBC_CRT1_PIE := $(GLIBC_BUILD)/csu/Scrt1.o
GLIBC_CRTI := $(GLIBC_BUILD)/csu/crti.o
GLIBC_CRTN := $(GLIBC_BUILD)/csu/crtn.o

GCC_CRTBEGIN_STATIC := $(shell gcc -print-file-name="crtbeginT.o")
GCC_CRTBEGIN_PIE := $(shell gcc -print-file-name="crtbeginS.o")
GCC_CRTBEGIN_NORMAL := $(shell gcc -print-file-name="crtbegin.o")
GCC_CRTEND := $(shell gcc -print-file-name="crtend.o")
GCC_CRTEND_PIE := $(shell gcc -print-file-name="crtendS.o")
GCC_INSTALL := $(shell gcc -print-search-dirs | grep 'install:' | sed -e 's,^install: ,,g')
GCC_LD := $(shell gcc -print-prog-name="collect2")

GLIBC_CRTS_NORMAL := $(GLIBC_CRT1) $(GLIBC_CRTI) $(GLIBC_CRTN)

GLIBC_LD_NORMAL = $(GCC_LD) --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 \
	$(GLIBC_DYNLINKER) $(GLIBC_LINKPATH) -o $@ $(GLIBC_CRT1) $(GLIBC_CRTI) $(GCC_CRTBEGIN_NORMAL) \
	-L$(GCC_INSTALL) -L$(GCC_INSTALL)/../../../../lib64 -L/lib/..lib64 -L/usr/lib/../lib64 \
	-L$(GCC_INSTALL)/../../.. -Map $@.map $< $(GLIBC_BUILD)/nptl/libpthread.so.0 \
	$(GLIBC_BUILD)/nptl/libpthread_nonshared.a -lgcc --as-needed -lgcc_s --no-as-needed \
	$(GLIBC_BUILD)/libc.so.6 $(GLIBC_BUILD)/libc_nonshared.a --as-needed $(GLIBC_BUILD)/elf/ld.so \
	--no-as-needed -lgcc --as-needed -lgcc_s --no-as-needed $(GCC_CRTEND) $(GLIBC_CRTN)

GLIBC_LD_STATIC = $(GCC_LD) --build-id --no-add-needed --hash-style=gnu -m elf_x86_64 -static -o \
	$@ $(GLIBC_CRT1) $(GLIBC_CRTI) $(GCC_CRTBEGIN_STATIC) -L$(GCC_INSTALL) \
	-L$(GCC_INSTALL)/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 \
	-L$(GCC_INSTALL)/../../..  -Map $@.map $< $(GLIBC_BUILD)/nptl/libpthread.a \
	--start-group -lgcc -lgcc_eh $(GLIBC_BUILD)/libc.a --end-group \
	$(GCC_CRTEND) $(GLIBC_CRTN)

GLIBC_CRTS_PIE := $(GLIBC_CRT1_PIE) $(GLIBC_CRTI) $(GLIBC_CRTN)

GLIBC_LD_PIE = $(GCC_LD) --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 \
	$(GLIBC_DYNLINKER) $(GLIBC_LINKPATH) -pie -o $@ $(GLIBC_CRT1_PIE) $(GLIBC_CRTI) $(GCC_CRTBEGIN_PIE) \
	-L$(GCC_INSTALL) -L$(GCC_INSTALL)/../../../../lib64 -L/lib/../lib64 \
	-L/usr/lib/../lib64 -L$(GCC_INSTALL)/../../..  -Map $@.map \
	$< $(GLIBC_BUILD)/nptl/libpthread.so.0 $(GLIBC_BUILD)/nptl/libpthread_nonshared.a \
	-lgcc --as-needed -lgcc_s --no-as-needed $(GLIBC_BUILD)/libc.so.6 \
	$(GLIBC_BUILD)/libc_nonshared.a --as-needed $(GLIBC_BUILD)/elf/ld.so --no-as-needed \
	-lgcc --as-needed -lgcc_s --no-as-needed $(GCC_CRTEND_PIE) $(GLIBC_CRTN)
