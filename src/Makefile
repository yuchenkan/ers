BUILD := ../build/src

.DEFAULT_GOAL := all
.SUFFIXES:

MAKE_SCRIPTS := Makefile

.PHONY: phony
define TOP =
ifeq ($(PASS),)
$1: phony
	mkdir -p $(BUILD)
	rm -f $(BUILD)/deps.mk
	+$(MAKE) $(MAKECMDGOALS) -B PASS=deps
	+$(MAKE) $(MAKECMDGOALS) PASS=work
	echo done
else ifeq ($(PASS),work)
$1: $2 $(MAKE_SCRIPTS)
	$3
.PRECIOUS: $1
else
$1: $2
	$4
endif
endef

, := ,
PREPS = $(filter-out $(MAKE_SCRIPTS),$^)

BUILD_TST := $(BUILD)/tst
GENERATED := $(BUILD)/generated

CFLAGS := $O -I . -I $(BUILD) -g -Wall -Werror -fno-tree-loop-distribute-patterns -mgeneral-regs-only -fno-builtin -fPIC -c -fvisibility=hidden
LDFLAGS := -nostdlib -Wl,--no-undefined -Wl,--fatal-warnings

COMPILE = mkdir -p $(@D) && gcc $(CFLAGS) -MM -MQ $@ -MP -MF $@.d $< && gcc $(CFLAGS) -o $@ $<
ADD_DEPS = echo -include $@.d >>$(BUILD)/deps.mk

EXP_OBJS = $(patsubst %,$(BUILD)/%.o,$1)

LIB_SRCS := buf.c lock.c malloc.c printf.c util.c syscall.l
LIB_OBJS := $(call EXP_OBJS,$(patsubst %,lib/%,$(LIB_SRCS)))

TST_LIVE_THREADS := tst-live-start tst-live-clone
TSTS := tst-rtld $(TST_LIVE_THREADS)
BUILD_TST_TST_OUTS := $(patsubst %,$(BUILD_TST)/%.out,$(TSTS))

$(eval $(call TOP,all,$(BUILD_TST_TST_OUTS)))
.PHONY: all

$(BUILD)/live-signal-thread.S.o: $(GENERATED)/live-signal-thread-local-offsets.h $(GENERATED)/lib/syscall-offsets.h
$(BUILD)/live-thread.S.o: $(GENERATED)/live-thread-local-offsets.h $(GENERATED)/lib/syscall-offsets.h

$(eval $(call TOP,$(BUILD)/rtld-convert,$(BUILD)/rtld-convert.c.o,gcc -o $$@ $$(PREPS)))
$(BUILD)/rtld-convert.c.o: private CFLAGS := $O -I . -Wall -Werror -g -c

$(BUILD)/%.so: private LDFLAGS += -shared

$(eval $(call TOP,$(BUILD)/%.l.o,$(BUILD)/%.c.o $(BUILD)/%.S.o,\
	ld -r $$(PREPS) -o $$@.c &&\
	nm -g --defined-only $$@.c | awk '{ print $$$$3 }' | grep -v '^eri_' >$$@.l &&\
	objcopy --localize-symbols=$$@.l $$@.c $$@))

$(eval $(call TOP,$(GENERATED)/%-offsets.h,%-offsets.c,\
	mkdir -p $$(@D) && \
	gcc -I . -MM -MQ $$@ -MP -MF $$@.d $$< &&\
	gcc -I . -Wall -Werror -O3 -S -o $$@.s $$< &&\
	grep __AS_DEFINE__ $$@.s | sed 's/__AS_DEFINE__/#define/g' >$$@,\
	$$(ADD_DEPS)))

$(eval $(call TOP,$(BUILD)/%.o,%,$$(COMPILE),$$(ADD_DEPS)))

TST_LDFLAGS = $(LDFLAGS) -Wl,-e,tst_start

BUILD_TST_RTLD := $(BUILD_TST)/rtld

$(BUILD_TST)/tst-rtld.out: $(BUILD_TST)/tst-rtld-recorder
$(BUILD_TST)/tst-rtld.out: private TST_ENVS := ERS_RECORDER=tst-rtld-recorder

$(eval $(call TOP,$(BUILD_TST)/tst-rtld-recorder $(BUILD_TST_RTLD)/generated/recorder-binary.h,\
		$(BUILD_TST)/tst-rtld-recorder.so $(BUILD)/rtld-convert,\
	mkdir -p $(BUILD_TST_RTLD)/generated &&\
	$(BUILD)/rtld-convert recorder $$< $(BUILD_TST)/tst-rtld-recorder $(BUILD_TST_RTLD)/generated/recorder-binary.h))

$(eval $(call TOP,$(BUILD_TST)/tst-rtld-recorder.so,\
		$(BUILD_TST)/tst-rtld-recorder.c.o $(BUILD_TST)/tst-rtld-recorder.S.o\
		$(LIB_OBJS),\
	gcc $$(TST_LDFLAGS) -o $$@ $$(PREPS)))

$(BUILD_TST)/tst-rtld-recorder.S.o: $(GENERATED)/rtld-offsets.h

$(eval $(call TOP,$(BUILD_TST)/tst-rtld,$(BUILD_TST)/tst-rtld.S.o,\
	gcc -nostdlib -pie -Wl$(,)-e$(,)start -o $$@ $$(PREPS)))

PUBLIC_IMPL_H_PREPS = $1/generated/public/rtld.h $(GENERATED)/public/entry-offsets.h

$(BUILD_TST)/tst-rtld.S.o: $(call PUBLIC_IMPL_H_PREPS,$(BUILD_TST_RTLD))
$(BUILD_TST)/tst-rtld.S.o: private CFLAGS := -I $(BUILD_TST_RTLD) $(filter-out -fPIC,$(CFLAGS)) -fPIE

$(eval $(call TOP,$(BUILD_TST_RTLD)/generated/public/rtld.h,\
		$(BUILD_TST_RTLD)/rtld $(BUILD)/rtld-convert,\
	mkdir -p $$(@D) &&\
	$(BUILD)/rtld-convert rtld $$< $$@))

$(eval $(call TOP,$(BUILD_TST_RTLD)/rtld,\
		rtld.ld $(BUILD_TST_RTLD)/rtld.l.o $(BUILD_TST_RTLD)/lib/util.c.o $(BUILD_TST_RTLD)/lib/printf.c.o,\
	gcc $$(LDFLAGS) -pie -Wl$(,)-Map$(,)$(BUILD_TST)/rtld/rtld.map -Wl$(,)-T$(,)$$<\
		-Wl$(,)-e$(,)eri_start -Wl$(,)--gc-sections -Wl$(,)-N -o $$@ $$(filter-out rtld.ld,$$(PREPS)) &&\
	objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id -R .dynsym\
		-R .dynstr -R .gnu.hash -R .rela.dyn -R .dynamic -R .got -R .got.plt $$@))

$(BUILD_TST_RTLD)/%.o: private CFLAGS := -I $(BUILD_TST_RTLD)\
			$(filter-out -fPIC,$(CFLAGS)) -fPIE -fdata-sections -ffunction-sections
$(BUILD_TST_RTLD)/rtld.c.o: $(BUILD_TST_RTLD)/generated/recorder-binary.h

$(eval $(call TOP,$(BUILD_TST_RTLD)/%.o,%,$$(COMPILE),$$(ADD_DEPS)))

TST_LIVE_THREADS_SRCS := tst/tst-common-start.S tst/tst-live-main.c\
		live-signal-thread.l live-thread.l helper.c live-thread-recorder.c
TST_LIVE_THREADS_OBJS := $(call EXP_OBJS,$(TST_LIVE_THREADS_SRCS)) $(LIB_OBJS)

$(foreach T,$(TST_LIVE_THREADS),\
	$(eval $(call TOP,$(BUILD_TST)/$T,\
			$(BUILD_TST)/$T.c.o $(TST_LIVE_THREADS_OBJS),\
		gcc $$(TST_LDFLAGS) -o $$@ $$(PREPS))))

TST_TST_RECORDER_H_PREPS := $(call PUBLIC_IMPL_H_PREPS,$(BUILD))
$(patsubst %,$(BUILD_TST)/%.c.o,$(TST_LIVE_THREADS)): $(TST_TST_RECORDER_H_PREPS)

# XXX
$(eval $(call TOP,$(GENERATED)/public/rtld.h,,mkdir -p $$(@D) && touch $$@))

$(eval $(call TOP,$(BUILD)/%.out,$(BUILD)/%,\
	cd $$(@D) && $$(TST_ENVS) ./$$(<F) 2>&1 | tee $$(<F).log;\
	test $$$${PIPESTATUS[0]} -eq 0 && touch $$(@F)))

clean:
	rm -rf $(BUILD)
.PHONY: clean

-include $(BUILD)/deps.mk
