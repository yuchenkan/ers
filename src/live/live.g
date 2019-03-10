'use strict'; /* vim: set ft=javascript: */

const convert = 'convert';
await this.update ([ convert, `${goal}.so` ]);

await env.run (`./${convert} ${goal}.so ${goal}`);
