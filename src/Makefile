RECORDER := rtld.c recorder.c common.c lib/printf.c lib/malloc.c lib/util.c lib/lock.c vex/vex.c
REPLAYER := replayer.c common.c lib/printf.c lib/util.c
TRACER := vex/tracer.c common.c lib/printf.c lib/util.c

BUILD := ../build/src
CFLAGS := -I . -O3 -g -Wall -fno-tree-loop-distribute-patterns -save-temps=obj -fPIC -fvisibility=hidden -mgeneral-regs-only

VEX_CFLAGS := -I $(BUILD)/vex -I ../3rd/xed/include/public -I ../3rd/xed/include/public/xed -I ../3rd/xed/obj
VEX_LDFLAGS := -Wl,--exclude-libs,ALL

MAKEFILES := Makefile
XED := ../3rd/xed/obj/libxed.a

all: $(BUILD)/librecorder.so $(BUILD)/replayer $(BUILD)/tracer

$(BUILD)/librecorder.so: $(patsubst %,$(BUILD)/%,$(RECORDER:.c=.o)) $(XED)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) $(VEX_LDFLAGS) -nostdlib -Wl,--no-undefined -shared -Wl,-e,entry -o $@ $^
	objdump -W $@ >$(@:.so=.dwarf)
	objdump -dSl $@ >$(@:.so=.asm)

$(BUILD)/librecorder.a: $(patsubst %,$(BUILD)/%,$(RECORDER:.c=.o))
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

$(XED):
	cd ../3rd/xed && ./mfile.py --extra-flags='-fPIC -g -mgeneral-regs-only'

$(BUILD)/vex/%: CFLAGS += $(VEX_CFLAGS)

$(BUILD)/vex/vex.o: $(BUILD)/vex/vex-offsets.h

$(BUILD)/%-offsets.h: %-offsets.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -MM -MQ $(@:.h=.s) -MP -MF $(@:.h=.d) $<
	gcc $(CFLAGS) -S -o $(@:.h=.s) $<
	grep __AS_DEFINE__ $(@:.h=.s) | sed 's/__AS_DEFINE__/#define/g' >$@

$(BUILD)/vex/tracer.o: CFLAGS := -g -I . -O3 -Wall

LIB_TSTS := malloc printf list rbtree
BUILD_TSTS := $(BUILD)/tst-asm $(patsubst %,$(BUILD)/lib/tst-%,$(LIB_TSTS))

check: $(BUILD_TSTS) $(patsubst %,%.out,$(BUILD_TSTS))

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

$(BUILD)/%.o: %.c $(MAKEFILES)
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -MM -MQ $@ -MP -MF $(@:.o=.d) $<
	gcc $(CFLAGS) -c -o $@ $<

-include $(patsubst %,$(BUILD)/%,$(RECORDER:.c=.d)) $(patsubst %,$(BUILD)/%,$(REPLAYER:.c=.d)) $(BUILD)/tst-asm.d $(BUILD)/vex/vex-offsets.d

.PHONY: all check
