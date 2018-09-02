BUILD := ../build/example

GLIBC_BUILD := /work/glibc-obj
GLIBC_SYSROOT := /work/glibc-local

DYNLINKER := --dynamic-linker=$(GLIBC_BUILD)/elf/ld.so
LINKPATH := -rpath=$(GLIBC_BUILD):$(GLIBC_BUILD)/math:$(GLIBC_BUILD)/elf:$(GLIBC_BUILD)/dlfcn:$(GLIBC_BUILD)/nss:$(GLIBC_BUILD)/nis:$(GLIBC_BUILD)/rt:$(GLIBC_BUILD)/resolv:$(GLIBC_BUILD)/crypt:$(GLIBC_BUILD)/mathvec:$(GLIBC_BUILD)/nptl

CRT1 := $(GLIBC_BUILD)/csu/crt1.o
CRT1_PIE := $(GLIBC_BUILD)/csu/Scrt1.o
CRTI := $(GLIBC_BUILD)/csu/crti.o
CRTN := $(GLIBC_BUILD)/csu/crtn.o

CRTBEGIN_STATIC := $(shell gcc -print-file-name="crtbeginT.o")
CRTBEGIN_PIE := $(shell gcc -print-file-name="crtbeginS.o")
CRTBEGIN_NORMAL := $(shell gcc -print-file-name="crtbegin.o")
CRTEND := $(shell gcc -print-file-name="crtend.o")
CRTEND_PIE := $(shell gcc -print-file-name="crtendS.o")
GCCINSTALL := $(shell gcc -print-search-dirs | grep 'install:' | sed -e 's,^install: ,,g')
LD := $(shell gcc -print-prog-name="collect2")

CFLAGS := -g3 -O0

MAKEFILES := Makefile

EXAMPLES := threads malloc clone
TARGETS := $(patsubst %,$(BUILD)/%,$(EXAMPLES)) $(patsubst %,$(BUILD)/%-normal,$(EXAMPLES)) $(patsubst %,$(BUILD)/%-static,$(EXAMPLES)) $(patsubst %,$(BUILD)/%-pie,$(EXAMPLES))

all: $(TARGETS)
	cp *.sh $(BUILD)

$(BUILD)/%-normal: $(BUILD)/%-normal.o $(CRT1) $(CRTI) $(CRTN)
	mkdir -p $(dir $@)
	$(LD) --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 \
		$(DYNLINKER) $(LINKPATH) -o $@ $(CRT1) $(CRTI) $(CRTBEGIN_NORMAL) \
		-L$(GCCINSTALL) -L$(GCCINSTALL)/../../../../lib64 -L/lib/..lib64 -L/usr/lib/../lib64 \
		-L$(GCCINSTALL)/../../.. -Map $@.map $< $(GLIBC_BUILD)/nptl/libpthread.so.0 \
		$(GLIBC_BUILD)/nptl/libpthread_nonshared.a -lgcc --as-needed -lgcc_s --no-as-needed \
		$(GLIBC_BUILD)/libc.so.6 $(GLIBC_BUILD)/libc_nonshared.a --as-needed $(GLIBC_BUILD)/elf/ld.so \
		--no-as-needed -lgcc --as-needed -lgcc_s --no-as-needed $(CRTEND) $(CRTN)

$(BUILD)/%-static: $(BUILD)/%-normal.o $(CRT1) $(CRTI) $(CRTN)
	mkdir -p $(dir $@)
	$(LD) --build-id --no-add-needed --hash-style=gnu -m elf_x86_64 -static -o \
		$@ $(CRT1) $(CRTI) $(CRTBEGIN_STATIC) -L$(GCCINSTALL) \
		-L$(GCCINSTALL)/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 \
		-L$(GCCINSTALL)/../../..  -Map $@.map $< $(GLIBC_BUILD)/nptl/libpthread.a \
		--start-group -lgcc -lgcc_eh $(GLIBC_BUILD)/libc.a --end-group \
		$(CRTEND) $(CRTN)

$(BUILD)/%-pie: $(BUILD)/%-pie.o $(CRT1_PIE) $(CRTI) $(CRTN)
	mkdir -p $(dir $@)
	$(LD) --build-id --no-add-needed --eh-frame-hdr --hash-style=gnu -m elf_x86_64 \
		$(DYNLINKER) $(LINKPATH) -pie -o $@ $(CRT1_PIE) $(CRTI) $(CRTBEGIN_PIE) \
		-L$(GCCINSTALL) -L$(GCCINSTALL)/../../../../lib64 -L/lib/../lib64 \
		-L/usr/lib/../lib64 -L$(GCCINSTALL)/../../..  -Map $@.map \
		$< $(GLIBC_BUILD)/nptl/libpthread.so.0 $(GLIBC_BUILD)/nptl/libpthread_nonshared.a \
		-lgcc --as-needed -lgcc_s --no-as-needed $(GLIBC_BUILD)/libc.so.6 \
		$(GLIBC_BUILD)/libc_nonshared.a --as-needed $(GLIBC_BUILD)/elf/ld.so --no-as-needed \
		-lgcc --as-needed -lgcc_s --no-as-needed $(CRTEND_PIE) $(CRTN)

$(BUILD)/%: $(BUILD)/%.o
	mkdir -p $(dir $@)
	gcc -o $@ $< -lpthread

$(BUILD)/%-normal.o: %.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc --sysroot=$(GLIBC_SYSROOT) $(CFLAGS) -M -MQ $@ -MP -MF $(@:.o=.d) $<
	gcc --sysroot=$(GLIBC_SYSROOT) $(CFLAGS) -c $< -o $@

$(BUILD)/%-pie.o: %.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc --sysroot=$(GLIBC_SYSROOT) -pie -fPIC $(CFLAGS) -M -MQ $@ -MP -MF $(@:.o=.d) $<
	gcc --sysroot=$(GLIBC_SYSROOT) -pie -fPIC $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -MM -MQ $@ -MP -MF $(@:.o=.d) $<
	gcc $(CFLAGS) -c $< -o $@

check:

-include $(patsubst %,$(BUILD)/%.d,$(EXAMPLES)) $(patsubst %,$(BUILD)/%.d,$(EXAMPLES))

.PHONY: all check
