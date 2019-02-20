'use strict'; /* vim: set ft=javascript: */

if (goal.match (/^lib\/tst\/tst-.*\.o$/))
  await this.invoke ('goal/compile.g', { cflags: (_, f) => f });
else
  await this.invoke ('goal/compile.g', { src: `lib/${goal.match (/^lib\/tst\/lib\/(.*).o$/)[1]}`, cflags: (_, f) => f });
