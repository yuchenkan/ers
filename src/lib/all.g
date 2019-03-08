'use strict'; /* vim: set ft=javascript: */

await this.update ([ 'atomic', 'list', 'rbtree', 'malloc', 'printf', 'util' ].map (t => `lib/tst/tst-${t}.out`));
