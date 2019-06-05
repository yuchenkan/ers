'use strict'; /* vim: set ft=javascript: */

await this.invoke ('replay/replay.g', { extra: [ 'analysis/thread.c.o', 'analysis/analyzer.c.o', 'analysis/translate.c.o', 'analysis/xed.gen/libxed.a' ] });
