'use strict'; /* vim: set ft=javascript: */

const { 1: src, 2: args } = goal.match (/^(live\/tst\/tst-[^.-]*-exit)-([^.]*).out$/);
await this.invoke (src === 'live/tst/tst-main-exit' ? 'tst/goal/out.g' : 'live/tst/tst-init.out.g', { src, args });
