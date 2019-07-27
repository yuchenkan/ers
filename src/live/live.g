'use strict'; /* vim: set ft=javascript: */

if (typeof plain === 'undefined') var plain = 'plain/plain.so';

const convert = 'live/convert';
await this.update ([ convert, plain, `${goal}.so` ]);

await env.run (`./${convert} bin ${plain} ${goal}.so ${goal}`);
