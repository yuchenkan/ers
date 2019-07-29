'use strict'; /* vim: set ft=javascript: */

let entries = [ 'syscall', 'sync-async' ];
entries = entries.concat ([ 'load', 'store', 'inc-dec', 'xchg', 'cmpxchg', 'cmp', 'and', 'or', 'xor', 'xadd' ].map (x => `atomic-${x}`));

return entries.map (t => `entry-${t}`).concat (await this.invoke ('live/tst/replay.g'));
