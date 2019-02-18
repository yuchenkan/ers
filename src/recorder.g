'use strict'; /* vim: set ft=javascript: */

let header = `${goal.replace (/recorder$/, 'generated/recorder-binary.h')}`;
await this.update ([ 'rtld-convert', `${goal}.so` ]);

await env.mkdir (header);
await env.run (`./rtld-convert recorder ${goal}.so ${goal} ${header}`);
