'use strict'; /* vim: set ft=javascript: */

if (typeof dispatch === 'undefined') var dispatch = false;

if (dispatch)
  return await subs.reduce (async (a, s) =>
      await a || (goal.startsWith (`${s}/`) && await this.invoke (`${s}/Goalfile`) !== false), false);

if (typeof extra === 'undefined') var extra = [ ];
await this.update (subs.map (s => `${s}/${env.base (goal)}`).concat (extra));
