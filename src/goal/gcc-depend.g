'use strict'; /* vim: set ft=javascript: */

if (typeof inc === 'undefined') var inc = f => typeof f === 'undefined' ? [ ] : f;

let incs = inc ().map (i => `-I ${i}`).join (' ');
await this.invoke ('goal/depend.g', { src, depend: async () => {
  await env.run (`gcc -I . ${incs} -x c -M -MG -MF ${goal}.d ${src}`, true);
  const data = await env.read (`${goal}.d`);
  return env.split (data.split (':')[1]).filter (x => x[0] !== '/').map (inc);
} });

return incs;
