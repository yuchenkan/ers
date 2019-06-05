'use strict'; /* vim: set ft=javascript: */

if (typeof srcs === 'undefined') var srcs = [ `${env.trim (goal)}.S.o`, `${env.trim (goal)}.c.o` ];
if (typeof keep === 'undefined') {
  let pfx = `${env.base (goal).startsWith ('tst-') ? 'tst' : 'eri'}_`;
  var keep = [ `^${pfx}`, `^_${pfx}` ];
}

await this.update (srcs);
await env.run (`ld --fatal-warnings -r ${srcs.join (' ')} -o ${goal}.o`);
await env.run (`nm -g --defined-only ${goal}.o | awk '{ print $3 }' | grep -v '${keep.join ('\\|')}' >${goal}.l || [[ $? == 1 ]]`);
await env.run (`[ -s ${goal}.l ] && objcopy --localize-symbols=${goal}.l ${goal}.o ${goal} || mv ${goal}.o ${goal}`);
