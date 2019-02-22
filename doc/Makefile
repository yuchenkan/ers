BUILD := ../build/doc
PLANTUML_JAR := $(abspath ../../plantuml.jar)

DIAGRAMS := class sig-timed-wait atomic-sync-signal exit retry-exit threads
all: $(DIAGRAMS)

$(DIAGRAMS): % : $(BUILD)/%.pdf

$(BUILD)/%.pdf: %.txt Makefile
	mkdir -p $(@D) && cp $< $(@D)
	cd $(@D) && java -jar $(PLANTUML_JAR) -tsvg $< && rsvg-convert -f pdf -o $(@F) $(@F:.pdf=.svg)
