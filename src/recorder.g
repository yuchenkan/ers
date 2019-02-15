'use strict'; /* vim: set ft=javascript: */

await this.update ([ 'rtld-convert', `${goal}.so` ], async () => {
  await env.run (`./rtld-convert recorder ${goal}.so ${goal} ${goal.replace (/recorder$/, 'generated/recorder-binary.h')}`);
});
