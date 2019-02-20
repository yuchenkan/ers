'use strict'; /* vim: set ft=javascript: */

await this.invoke ('goal/depend.g', { src, depend: async () => {
  await env.run (`gcc -I . -M -MG -MF ${goal}.d ${src}`, true);
  const data = await env.read (`${goal}.d`);
  return env.split (data.split (':')[1]).filter (x => x[0] !== '/');
} });
