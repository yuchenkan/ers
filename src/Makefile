RECORDER := recorder.c common.c lib/printf.c lib/malloc.c lib/util.c
REPLAYER := replayer.c common.c lib/printf.c lib/util.c

CFLAGS := -O3 -g -Wall -fno-tree-loop-distribute-patterns -save-temps=obj -fPIC
BUILD := ../build/src

MAKEFILES := Makefile

all: $(BUILD)/librecorder.so $(BUILD)/replayer

$(BUILD)/librecorder.so: $(patsubst %,$(BUILD)/%,$(RECORDER:.c=.o))
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -nostdlib -Wl,--no-undefined -shared -fvisibility=hidden -o $@ $^
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

LIB_TSTS := malloc printf list rbtree

check: $(BUILD)/tst-asm.out $(patsubst %,$(BUILD)/lib/tst-%.out, $(LIB_TSTS))

$(BUILD)/%.out: $(BUILD)/%
	cd $(dir $@) && ./$(notdir $<) && touch $(notdir $@)

$(BUILD)/tst-%: $(BUILD)/tst-%.o $(BUILD)/librecorder.a
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -o $@ $^
	objdump -W $@ >$@.dwarf
	objdump -dSl $@ >$@.asm

$(BUILD)/lib/tst-%: $(BUILD)/lib/tst-%.o $(BUILD)/librecorder.a
	mkdir -p $(dir $@)
	gcc $(CFLAGS) -o $@ $^

$(BUILD)/%.o: %.c $(MAKEFILES)
	mkdir -p $(dir $@)
	@gcc $(CFLAGS) -MM -MQ $@ -MP -MF $(@:.o=.d) $<
	gcc $(CFLAGS) -c -o $@ $<

-include $(patsubst %,$(BUILD)/%,$(RECORDER:.c=.d)) $(patsubst %,$(BUILD)/%,$(REPLAYER:.c=.d)) $(BUILD)/tst-asm.d

.PHONY: all check
