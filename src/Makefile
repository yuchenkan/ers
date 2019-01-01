BUILD := ../build/src
MAKE_FILES := Makefile common.mk $(BUILD)/O $(BUILD)/D

include common.mk

EXP_OBJS = $(patsubst %,$(BUILD)/%.os,$1)

LIB_SRCS := buf.c lock.c malloc.c printf.c util.c syscall.S
LIB_OBJS := $(call EXP_OBJS,$(patsubst %,lib/%,$(LIB_SRCS)))

OBJS = $(call EXP_OBJS,$(SRCS))

CFLAGS = $O $D -I . -I $(BUILD) -g -Wall -Werror \
		-fno-tree-loop-distribute-patterns -fvisibility=hidden \
		-mgeneral-regs-only -c
LDFLAGS = -nostdlib -Wl,--no-undefined -Wl,--fatal-warnings

define PROG =
DEPS += $(call EXP_OBJS,$2)
$1: $(call EXP_OBJS,$2) $$(LIB_OBJS)
	gcc $$(LDFLAGS) -o $$@ $$^
endef

DEPS := $(LIB_OBJS)

all: $(BUILD)/rtld-convert tests

DEPS += $(BUILD)/rtld-convert.c.o
$(BUILD)/rtld-convert: % : %.c.o
	gcc $^ -o $@

PUBLIC_IMPL_H_PRES := $(BUILD)/public/entry-offsets.h
PUBLIC_IMPL_H_DEPS := $(BUILD)/public/entry-offsets.h.s

$(BUILD)/rtld-convert.c.o: private CFLAGS := $O -I . -Wall -Werror -g -c

$(BUILD)/%-offsets.h: $(BUILD)/%-offsets.h.s
	grep __AS_DEFINE__ $< | sed 's/__AS_DEFINE__/#define/g' >$@

$(BUILD)/%-offsets.h.s: private CFLAGS := -I . -Wall -Werror -O3 -S
$(BUILD)/%-offsets.h.s: %-offsets.c Makefile
	$(COMPILE)

TST_LIVE_QUIT_TSTS := basic clone join ctid-segv group
TST_LIVE_ENTRY_TSTS := start basic clone sig-ignore restart nested-invoke

TST_TSTS := rtld $(patsubst %,live-quit-%,$(TST_LIVE_QUIT_TSTS)) \
	$(patsubst %,live-entry-%,$(TST_LIVE_ENTRY_TSTS))

BUILD_TST := $(BUILD)/tst
BUILD_TST_TSTS := $(patsubst %,$(BUILD_TST)/tst-%,$(TST_TSTS)) \

tests: $(BUILD_TST_TSTS)

check: $(BUILD_TST_TSTS) \
	$(filter-out %/tst-live-entry-basic.out,$(BUILD_TST_OUTS))
	echo done

full-check: $(BUILD_TST_TSTS) $(BUILD_TST_OUTS)
	echo done


re-check: $(BUILD_TST_TSTS) \
	$(filter-out %/tst-live-entry-basic.re-check,$(BUILD_TST_RE_CHECKS))
	echo done

full-re-check: $(BUILD_TST_TSTS) $(BUILD_TST_RE_CHECKS)
	echo done

# tst-rtld

BUILD_TST_RTLD := $(BUILD_TST)/rtld

$(BUILD_TST)/tst-rtld.out: $(BUILD_TST)/tst-rtld-recorder

$(BUILD_TST)/tst-rtld: % : %.S.o
	gcc -nostdlib -pie -Wl,-e,start -o $@ $<

TST_RTLD_PUBLIC_IMPL_H_PRES := $(BUILD)/public/entry-offsets.h \
				$(BUILD_TST_RTLD)/public/rtld.h
TST_RTLD_PUBLIC_IMPL_H_DEPS := $(BUILD)/public/entry-offsets.h.s \
				$(BUILD_TST)/tst-rtld.S.o

DEPS += $(TST_RTLD_PUBLIC_IMPL_H_DEPS)
$(BUILD_TST)/tst-rtld.S.o: private CFLAGS += -D ERI_TST_RTLD -fPIE
$(BUILD_TST)/tst-rtld.S.o: $(TST_RTLD_PUBLIC_IMPL_H_PRES)

$(BUILD_TST_RTLD)/public/rtld.h: $(BUILD_TST_RTLD)/rtld $(BUILD)/rtld-convert
	mkdir -p $(@D)
	$(BUILD)/rtld-convert rtld $< $@

BUILD_TST_RTLD2_SRCS := rtld.S rtld.c lib/util.c lib/printf.c
BUILD_TST_RTLD2_OBJS := \
		$(patsubst %,$(BUILD_TST_RTLD)/%.o,$(BUILD_TST_RTLD2_SRCS))

DEPS += $(BUILD_TST_RTLD2_OBJS)
$(BUILD_TST_RTLD)/rtld: rtld.ld $(BUILD_TST_RTLD2_OBJS)
	gcc $(LDFLAGS) -pie -Wl,-Map,$(BUILD_TST_RTLD)/rtld.map -Wl,-T,$< \
		-Wl,-e,eri_start -Wl,--gc-sections -Wl,-N \
		-o $@ $(BUILD_TST_RTLD2_OBJS)
	objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id -R .dynsym \
		-R .dynstr -R .gnu.hash -R .rela.dyn -R .dynamic -R .got -R .got.plt \
		$@

$(BUILD_TST_RTLD)/%.o: private CFLAGS += -D ERI_TST_RTLD \
				-fPIE -fdata-sections -ffunction-sections
$(BUILD_TST_RTLD)/rtld.c.o: $(BUILD_TST)/tst-rtld-recorder-binary.h

$(BUILD_TST_RTLD)/%.o: % $(MAKE_FILES)
	$(COMPILE)

$(BUILD_TST)/tst-rtld-recorder $(BUILD_TST)/tst-rtld-recorder-binary.h: \
		$(BUILD_TST)/tst-rtld-recorder.so $(BUILD)/rtld-convert
	$(BUILD)/rtld-convert recorder $< $(BUILD_TST)/tst-rtld-recorder \
		$(BUILD_TST)/tst-rtld-recorder-binary.h

$(eval $(call PROG,$(BUILD_TST)/tst-rtld-recorder.so,\
	tst/tst-rtld-recorder.c tst/tst-rtld-recorder.S))

$(BUILD_TST)/tst-rtld-recorder.S.os: $(BUILD)/rtld-offsets.h

# tst

$(BUILD_TST)/tst-%: private LDFLAGS += -Wl,-e,tst_start

# tst-live-quit

TST_LIVE_QUIT_COMMON_SRCS := tst/tst-common-start.S \
		tst/tst-live-quit-common.S tst/tst-live-quit-common.c \
		live.S live.c common.S common.c loop.c

$(foreach tst,$(patsubst %,tst-live-quit-%,$(TST_LIVE_QUIT_TSTS)),\
	$(eval $(call PROG,$(BUILD_TST)/$(tst),\
		$(TST_LIVE_QUIT_COMMON_SRCS) tst/$(tst).c)))

$(BUILD_TST)/tst-live-quit-common.S.os: $(BUILD)/rtld-offsets.h \
		$(BUILD)/live-entry-offsets.h

# tst-live-entry

TST_LIVE_ENTRY_START_SRCS := tst/tst-live-entry-common.c \
		tst/tst-live-entry-start.S tst/tst-live-entry-start.c \
		live-entry.c live-entry.S lib/tst/tst-util.c

TST_LIVE_ENTRY_COMMON_SRCS := tst/tst-common-start.S \
		tst/tst-live-entry-common.S tst/tst-live-entry-common.c \
		live-entry.S live-entry.c lib/tst/tst-util.c

TST_LIVE_ENTRY_BASIC_SRCS := $(TST_LIVE_ENTRY_COMMON_SRCS) \
		tst/tst-live-entry-basic.S tst/tst-live-entry-basic.c

TST_LIVE_ENTRY_CLONE_SRCS := $(TST_LIVE_ENTRY_COMMON_SRCS) \
		tst/tst-live-entry-clone.S tst/tst-live-entry-clone.c

TST_LIVE_ENTRY_SIG_IGNORE_SRCS := $(TST_LIVE_ENTRY_COMMON_SRCS) \
		tst/tst-live-entry-sig-ignore.c

TST_LIVE_ENTRY_RESTART_SRCS := $(TST_LIVE_ENTRY_COMMON_SRCS) \
		tst/tst-live-entry-restart.S tst/tst-live-entry-restart.c

TST_LIVE_ENTRY_NESTED_INVOKE_SRCS := $(TST_LIVE_ENTRY_COMMON_SRCS) \
		tst/tst-live-entry-nested-invoke.c

$(eval $(call PROG,$(BUILD_TST)/tst-live-entry-start,\
		$(TST_LIVE_ENTRY_START_SRCS)))

$(eval $(call PROG,$(BUILD_TST)/tst-live-entry-basic,\
		$(TST_LIVE_ENTRY_BASIC_SRCS)))

$(eval $(call PROG,$(BUILD_TST)/tst-live-entry-clone,\
		$(TST_LIVE_ENTRY_CLONE_SRCS)))

$(eval $(call PROG,$(BUILD_TST)/tst-live-entry-sig-ignore,\
		$(TST_LIVE_ENTRY_SIG_IGNORE_SRCS)))

$(eval $(call PROG,$(BUILD_TST)/tst-live-entry-restart,\
		$(TST_LIVE_ENTRY_RESTART_SRCS)))

$(eval $(call PROG,$(BUILD_TST)/tst-live-entry-nested-invoke,\
		$(TST_LIVE_ENTRY_NESTED_INVOKE_SRCS)))

DEPS += $(BUILD)/public/entry-offsets.h.s \
	$(BUILD)/rtld-offsets.h.s $(BUILD)/live-entry-offsets.h.s \
	$(BUILD)/lib/syscall-offsets.h.s \
	$(BUILD_TST)/tst-live-entry-common-offsets.h.s \
	$(PUBLIC_IMPL_H_DEPS)

$(BUILD)/live-entry.S.os: $(BUILD)/public/entry-offsets.h \
		$(BUILD)/rtld-offsets.h $(BUILD)/live-entry-offsets.h \
		$(BUILD)/lib/syscall-offsets.h

$(BUILD_TST)/tst-live-entry-common.S.os: \
		$(BUILD_TST)/tst-live-entry-common-offsets.h

$(BUILD_TST)/tst-live-entry-basic.S.os: \
		$(BUILD_TST)/tst-live-entry-common-offsets.h \
		$(PUBLIC_IMPL_H_PRES)

$(BUILD_TST)/tst-live-entry-clone.S.os: $(BUILD)/live-entry-offsets.h \
		$(PUBLIC_IMPL_H_PRES)

$(BUILD_TST)/tst-live-entry-restart.S.os: $(PUBLIC_IMPL_H_PRES)

$(BUILD)/%.so: private LDFLAGS += -shared

-include $(patsubst %,%.d,$(DEPS))

all tests check full-check re-check full-re-check clean: lib

lib:
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: all tests check full-check re-check full-re-check lib
