BUILD := ../../build/src/lib/tst
MAKE_FILES := Makefile ../common.mk $(BUILD)/O

include ../common.mk

TST_TSTS := atomic list rbtree malloc printf

BUILD_TST := $(BUILD)
BUILD_TST_TSTS := $(patsubst %,$(BUILD_TST)/tst-%,$(TST_TSTS))

BUILD_TST_OUTS := $(patsubst %,%.out,$(BUILD_TST_TSTS))
BUILD_TST_RE_CHECKS := $(patsubst %,%.re-check,$(BUILD_TST_TSTS))

all: tests

tests: $(BUILD_TST_TSTS)

check full-check: $(BUILD_TST_TSTS) $(BUILD_TST_OUTS)

re-check full-re-check: $(BUILD_TST_TSTS) $(BUILD_TST_RE_CHECKS)

CFLAGS := $O -I .. -g -c

DEPS += $(BUILD)/tst/tst-atomic.c.o
$(BUILD)/tst-atomic: $(BUILD)/tst/tst-atomic.c.o
	gcc -o $@ $^

PRINTF_SRCS := util.c lock.c buf.c printf.c
PRINTF_OBJS := $(patsubst %,$(BUILD)/%.o,$(PRINTF_SRCS))

$(BUILD)/tst-list: $(BUILD)/tst/tst-list.c.o $(PRINTF_OBJS)
	gcc -o $@ $^

$(BUILD)/tst-rbtree: $(BUILD)/tst/tst-rbtree.c.o $(PRINTF_OBJS)
	gcc -o $@ $^

MALLOC_SRCS := util.c lock.c buf.c malloc.c
MALLOC_OBJS := $(patsubst %,$(BUILD)/%.o,$(MALLOC_SRCS))

$(BUILD)/tst-malloc: $(BUILD)/tst/tst-malloc.c.o \
			$(MALLOC_OBJS) $(BUILD)/tst/tst-util.c.o
	gcc -o $@ $^

$(BUILD)/tst-printf: $(BUILD)/tst/tst-printf.c.o \
			$(PRINTF_OBJS) $(MALLOC_OBJS)
	gcc -o $@ $^

-include $(patsubst %,%.d,$(DEPS))

.PHONY: all tests check full-check re-check full-re-check
