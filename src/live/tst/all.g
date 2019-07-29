'use strict'; /* vim: set ft=javascript: */

const full = x => `live/tst/${x}`;

let tsts = [ 'rtld', 'sig-mask-async-ut' ];
tsts = tsts.concat ([ 'main', 'syscall', 'sync-async', 'atomic', 'atomic-ext', 'sig-action' ].map (x => `sig-hand-${x}-ut`));
tsts = tsts.concat ((await this.invoke (full ('diverge.g'))).map (t => `init-diverge-${t}`));

let commons = await this.invoke (full ('plain.g'));

tsts = tsts.concat (commons.map (t => `main-${t}`)).concat (commons.map (t => `init-${t}`));

await this.update ([ full ('loop.sh') ].concat (tsts.map (t => full (`tst-${t}.out`))));

//await this.update ([ 'tst/tst-live-sig-hand-sig-action-ut.out' ]);
