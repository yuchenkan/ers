'use strict'; /* vim: set ft=javascript: */

if (typeof srcs === 'undefined') var srcs = [ `${env.trim (goal)}.S.o`, `${env.trim (goal)}.c.o` ];
if (typeof keep === 'undefined') var keep = [ `^${env.base (goal).startsWith ('tst-') ? 'tst' : 'eri'}_` ];

await this.update (srcs);
await env.run (`ld --fatal-warnings -r ${srcs.join (' ')} -o ${goal}.o`);
await env.run (`nm -g --defined-only ${goal}.o | awk '{ print $3 }' | grep -v '${keep.join ('\\|')}' >${goal}.l`);
await env.run (`objcopy --localize-symbols=${goal}.l ${goal}.o ${goal}`);
