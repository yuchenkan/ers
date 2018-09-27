include ../my-glibc.mk
 
BUILD := ../build/src
.DEFAULT_GOAL := all

define DEPENDABLE_VAR

.PHONY: phony
$(BUILD)/$1: phony
	@if [[ `cat $(BUILD)/$1 2>&1` != '$($1)' ]]; then \
	  echo -n $($1) >$(BUILD)/$1; \
	fi

endef

O := -O3
$(eval $(call DEPENDABLE_VAR,O))
$(eval $(call DEPENDABLE_VAR,D))

LIB := lib/printf.c lib/malloc.c lib/util.c lib/lock.c
LIB_RECORDER := rtld.c recorder.c common.c vex/vex.c $(LIB)
REPLAYER := replayer.c common.c lib/printf.c lib/util.c
TRACER := tracer.c common.c lib/printf.c lib/util.c

CFLAGS := $O $D -I. -I$(BUILD) -g -Wall -fno-tree-loop-distribute-patterns -save-temps=obj -fPIC -fvisibility=hidden -mgeneral-regs-only
LIB_LDFLAGS := -nostdlib -Wl,--no-undefined -shared

VEX_CFLAGS := -I$(BUILD)/vex -I../3rd/xed/include/public -I../3rd/xed/include/public/xed -I../3rd/xed/obj
VEX_LDFLAGS := -Wl,--exclude-libs,ALL

MAKEFILES := ../my-glibc.mk Makefile $(BUILD)/O $(BUILD)/D
XED := ../3rd/xed/obj/libxed.a

LIB_TST_VEX := vex/tst-vex-entry.c vex/vex.c common.c $(LIB)
BUILD_VEX_TSTS := $(BUILD)/vex/tst-vex $(BUILD)/vex/tst-vex-simple

all: $(BUILD)/librecorder.so $(BUILD)/replayer $(BUILD)/tracer $(BUILD)/tracee vex

vex: $(BUILD_VEX_TSTS)
	cp vex/*.sh $(BUILD)/vex

$(BUILD)/librecorder.so: $(patsubst %,$(BUILD)/%,$(LIB_RECORDER:.c=.o)) $(XED) \
			 $(BUILD)/recorder-common-offsets.h
	mkdir -p $(dir $@)
	gcc $(CFLAGS) $(VEX_LDFLAGS) $(LIB_LDFLAGS) -Wl,-e,entry -o $@ $^
	objdump -W $@ >$(@:.so=.dwarf)
	objdump -dSl $@ >$(@:.so=.asm)

$(BUILD)/librecorder.a: $(patsubst %,$(BUILD)/%,$(LIB_RECORDER:.c=.o))
	mkdir -p $(dir $@)
	ar rcs $@ $^

$(BUILD)/replayer: $(patsubst %,$(BUILD)/%,$(REPLAYER:.c=.o))
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -nostdlib -o $@ $^
	objdump -W $@ >$@.dwarf
	objdump -dSl $@ >$@.asm

$(BUILD)/tracer: $(patsubst %,$(BUILD)/%,$(TRACER:.c=.o))
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -o $@ $^

$(BUILD)/recorder.o: $(BUILD)/recorder-offsets.h

$(XED):
	cd ../3rd/xed && ./mfile.py --extra-flags='-fPIC -g -mgeneral-regs-only'

$(BUILD)/vex/%: CFLAGS += $(VEX_CFLAGS)

$(BUILD)/vex/vex.o: $(BUILD)/vex/vex-offsets.h

$(BUILD)/%-offsets.h: %-offsets.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -MM -MQ $(@:.h=.s) -MP -MF $(@:.h=.d) $<
	gcc $(CFLAGS) -O3 -S -o $(@:.h=.s) $<
	grep __AS_DEFINE__ $(@:.h=.s) | sed 's/__AS_DEFINE__/#define/g' >$@

$(BUILD)/tracer.o: CFLAGS := -g -I. -O3 -Wall

LIB_TSTS := malloc printf list rbtree
BUILD_TSTS := $(BUILD)/tst-asm $(patsubst %,$(BUILD)/lib/tst-%,$(LIB_TSTS))
BUILD_TSTS_OUT := $(patsubst %,%.out,$(BUILD_TSTS))

check: $(BUILD_TSTS) $(BUILD_TSTS_OUT)
	cp vex/*.sh $(BUILD)/vex

$(BUILD)/%.out: $(BUILD)/%
	cd $(dir $@) && ./$(notdir $<) && touch $(notdir $@)

$(BUILD)/tst-%: $(BUILD)/tst-%.o $(BUILD)/librecorder.a $(XED)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -o $@ $^
	objdump -W $@ >$@.dwarf
	objdump -dSl $@ >$@.asm

$(BUILD)/lib/tst-%: $(BUILD)/lib/tst-%.o $(BUILD)/librecorder.a $(XED)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -o $@ $^

$(patsubst %,%.o,$(BUILD_VEX_TSTS)): CFLAGS := -g -O3 -Wall

$(BUILD)/vex/tst-vex-simple: CFLAGS += -nostdlib

$(BUILD)/vex/tst-vex-simple: $(BUILD)/vex/tst-vex-simple.o $(BUILD)/vex/libtst-vex.so
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -L$(BUILD)/vex -ltst-vex -o $@ $<

$(BUILD)/vex/tst-vex: $(BUILD)/vex/tst-vex.o $(BUILD)/vex/libtst-vex.so $(GLIBC_CRTS_NORMAL)
	mkdir -p $(dir $@)
	$(GLIBC_LD_NORMAL) -L$(BUILD)/vex -ltst-vex

$(BUILD)/vex/libtst-vex.so: $(patsubst %,$(BUILD)/%,$(LIB_TST_VEX:.c=.o)) $(XED)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) $(VEX_LDFLAGS) $(LIB_LDFLAGS) -o $@ $^
	objdump -dSl $@ >$(@:.so=.asm)

$(BUILD)/tracee: tracee.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc -MM -MQ $@ -MP -MF $(@).d $<
	gcc -lpthread $< -o $@

$(BUILD)/%.o: %.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -MM -MQ $@ -MP -MF $(@:.o=.d) $<
	gcc $(CFLAGS) -c -o $@ $<

SOURCES := $(shell find $(SOURCEDIR) -name '*.c')
-include $(patsubst %,$(BUILD)/%,$(SOURCES:.c=.d))

.PHONY: all vex check
