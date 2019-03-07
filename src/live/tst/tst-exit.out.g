'use strict'; /* vim: set ft=javascript: */

const { 1: src, 2: args } = goal.match (/^(live\/tst\/tst-[^.-]*-exit)-([^.]*).out$/);
await this.invoke ('goal/tst/out.g', { src, args });
