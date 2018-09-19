BUILD := ../build/examples

include ../my-glibc.mk
GLIBC_DYNLINKER := --dynamic-linker=$(abspath ../build/src/librecorder.so)

CFLAGS := -g3 -O0

MAKEFILES := ../my-glibc.mk Makefile

EXAMPLES := threads malloc clone
TARGETS := $(patsubst %,$(BUILD)/%,$(EXAMPLES)) $(patsubst %,$(BUILD)/%-normal,$(EXAMPLES)) $(patsubst %,$(BUILD)/%-static,$(EXAMPLES)) $(patsubst %,$(BUILD)/%-pie,$(EXAMPLES))

all: $(TARGETS)
	cp *.sh $(BUILD)

$(BUILD)/%-normal: $(BUILD)/%-normal.o $(GLIBC_CRTS_NORMAL)
	mkdir -p $(dir $@)
	$(GLIBC_LD_NORMAL)

$(BUILD)/%-static: $(BUILD)/%-normal.o $(GLIBC_CRTS_NORMAL)
	mkdir -p $(dir $@)
	$(GLIBC_LD_STATIC)

$(BUILD)/%-pie: $(BUILD)/%-pie.o $(CRT1_PIE) $(CRTI) $(CRTN)
	mkdir -p $(dir $@)
	$(GLIBC_LD_PIE)

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

-include $(patsubst %,$(BUILD)/%.d,$(EXAMPLES))

.PHONY: all check
