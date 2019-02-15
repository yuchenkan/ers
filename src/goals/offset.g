'use strict'; /* vim: set ft=javascript: */

await this.update ([ `${goal}.c.d` ], async () => {
  await env.run (`gcc -I . -Wall -Werror -O3 -S -o ${goal}.s ${goal}.c`);
  await env.run (`grep __AS_DEFINE__ ${goal}.s | sed 's/__AS_DEFINE__/#define/g' >${goal}`);
});
