'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${env.trim (goal)}.S.o`, `${env.trim (goal)}.c.o` ];
await this.update (srcs, async () => {
  await env.run (`ld -r ${srcs.join (' ')} -o ${goal}.o`);
  await env.run (`nm -g --defined-only ${goal}.o | awk '{ print $3 }' | grep -v '^eri_' >${goal}.l`);
  await env.run (`objcopy --localize-symbols=${goal}.l ${goal}.o ${goal}`);
});
