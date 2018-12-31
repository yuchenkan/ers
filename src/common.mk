.DEFAULT_GOAL := all
.SUFFIXES:

define DEPENDABLE_VAR =
.PHONY: phony
$(BUILD)/$1: phony
	@if [[ `cat $(BUILD)/$1 2>&1` != '$($1)' ]]; then \
	  mkdir -p $(BUILD); \
	  echo -n $($1) >$(BUILD)/$1; \
	fi

endef

O := -O3
$(eval $(call DEPENDABLE_VAR,O))
$(eval $(call DEPENDABLE_VAR,D))

BUILD_TST_OUTS = $(patsubst %,%.out,$(BUILD_TST_TSTS))
BUILD_TST_RE_CHECKS = $(patsubst %,%.re-check,$(BUILD_TST_TSTS))

$(BUILD)/%.out: $(BUILD)/%
	cd $(@D) && ./$(<F) 2>&1 | tee $(<F).log; \
		test $${PIPESTATUS[0]} -eq 0 && touch $(@F)

tst-re-check:

$(BUILD)/%.re-check: tst-re-check
	cd $(@D) && ./$(@F:.re-check=) 2>&1 | tee $(@F:.re-check=.log)

MAKEDEPS = gcc -MM -MQ $@ -MP -MF $@.d $<
COMPILE = mkdir -p $(@D) && $(MAKEDEPS) $(CFLAGS) && gcc $(CFLAGS) -o $@ $<

$(BUILD)/%.o: % $(MAKE_FILES)
	$(COMPILE)

$(BUILD)/%.os: private CFLAGS += -fPIC

$(BUILD)/%.os: % $(MAKE_FILES)
	$(COMPILE)

clean:
	rm -rf $(BUILD)

.PHONY: clean tst-re-check
