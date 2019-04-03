'use strict'; /* vim: set ft=javascript: */

const subs = [ 'tst' ].map (s => `${cur}/${s}`);
const base = goal.replace (new RegExp (`^${cur}/`), '');

if (await this.invoke ('goal/subs.g', { subs, dispatch: true })) return;
if (base === 'all') return await this.invoke ('goal/subs.g', { subs });

return base;
