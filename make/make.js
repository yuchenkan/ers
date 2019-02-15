'use strict';

const util = require ('util');
const assert = require ('assert');
const path = require ('path');
const fs = require ('fs');

const fstat = util.promisify (fs.fstat);
const open = util.promisify (fs.open);
const close = util.promisify (fs.close);
const readFile = util.promisify (fs.readFile);

const exec = util.promisify (require ('child_process').exec);

const AsyncFunction = Object.getPrototypeOf (async function () { }).constructor;

const debug = msg => {
  if (process.argv.length > 2) console.log (`[debug] ${msg}`);
}

const info = msg => console.log ('\x1b[33m%s\x1b[0m', `[info] ${msg}`);
const note = msg => console.log ('\x1b[32m%s\x1b[0m', `[note] ${msg}`);
const fatal = msg => console.log ('\x1b[31m%s\x1b[0m', `[fatal] ${msg}`);

function error (msg) {

  if (msg === undefined) return process.exitCode;

  fatal (`\n${msg}`);
  process.exitCode = 1;
}

async function read (file, opt) {

  try {
    var fd = await open (file, 'r');
  } catch (err) {
    if (opt && err.code === 'ENOENT') return null;
    throw err;
  }

  try {
    return await readFile (fd);
  } finally {
    await close (fd);
  }
}

async function stat (file, opt) {
  try {
    var fd = await open (file, 'r');
  } catch (err) {
    if (opt && err.code === 'ENOENT') return null;
    throw err;
  }

  try {
    return await fstat (fd);
  } finally {
    await close (fd);
  }
}

const context = (env, goal) => ({ update: env.update, invoke: env.invoke, env, goal });

const wait = async list => await new Promise ((res, rej) => list.push ({ res, rej }));
const wake = (list, all) => all ? list.map (x => x.res ()) : list.shift ().res ();

async function invoke (script, args) {

  const { env, goal } = this;
  debug (`invoke ${script} ${goal} [ ${args ? Object.keys (args).join (', ') : ''} ]`);

  if (args === undefined) args = { };

  const keys = Object.keys (args);
  assert (keys.every (k => k.match (',') === null));
  const name = `${path.normalize (path.relative ('.', script))}//${keys}`;

  try {

    if (name in env.invokes) {

      if (! env.invokes[name].updated) await wait (env.invokes[name].waiting);

      if (env.invokes[name].err !== undefined) throw env.invokes[name].err;

    } else {

      env.invokes[name] = { updated: false, waiting: [ ], fn: null };
      try {
	let decl = [ null, 'env', 'goal' ].concat (keys).concat (await env.read (script));
	env.invokes[name].fn = new (AsyncFunction.bind.apply (AsyncFunction, decl));
      } catch (err) {
	env.invokes[name].err = err;
	throw err;
      } finally {
	env.invokes[name].updated = true;
	wake (env.invokes[name].waiting, true);
      }
    }

    return await env.invokes[name].fn.apply (this, [ env, goal ].concat (keys.map (k => args[k])));

  } catch (err) {
    if (err !== null) err.stack = `  by ${script}: ${env.goals[script].deps}\n${err.stack}`;
    throw err;
  }
}

const ext = (f, e) => f.endsWith (`.${e}`);
const exts = (f, es) => ! es.every (e => ! ext (f, e));

const goalScript = g => ext (g, 'g') ? 'Goalfile' : `${g}.g`;

async function build (internal) {

  if (error ()) throw null;

  const { env, goal } = this;

  if (! internal) {

    if (goal in env.goals) {

      if (! env.goals[goal].updated) await wait (env.goals[goal].waiting);

      if (env.goals[goal].err !== undefined) throw env.goals[goal].err;
    } else {

      env.goals[goal] = { updated: false, waiting: [ ] };

      try {
	await build.call (this, true);
      } catch (err) {
	env.goals[goal].err = err;
	throw err;
      }finally {
	env.goals[goal].updated = true;
	wake (env.goals[goal].waiting, true);
      }
    }

    return;
  }

  debug (`build ${goal}`);

  if (goal === 'Goalfile')
    await this.update ([ env.src (goal) ], async () => await env.run (`cp ${env.src (goal)} ${goal}`));
  else {
    let script = goalScript (goal);
    env.goals[goal].edges = [ script ];
    await build.call (context (env, script));
    await this.invoke (script);

    await env.stat (goal);
  }
}

async function run (cmd, quiet) {

  const env = this;

  if (env.jobs === env.maxJobs) await wait (env.waiting);
  else ++env.jobs;

  (quiet ? debug : info) (cmd);

  try {
    let { stdout, stderr } = await exec (cmd);
    process.stdout.write (stdout);
  } finally {
    if (env.waiting.length) wake (env.waiting, false);
    else --env.jobs;
  }
}

async function outdated (deps) {

  const { env, goal } = this;

  const goalStat = await env.stat (goal, true);
  const depStats = await Promise.all (deps.map (d => env.stat (d, goalStat !== null).then (s => ({ d, s }))));

  const log = debug;
  if (goalStat !== null) {
    let up = depStats.filter (s => s.s === null || s.s.ctimeMs >= goalStat.ctimeMs);
    log (`outdated ${goal} existed and order than [ ${up.map (u => u.d).join (', ')} ] of [ ${ deps.join (', ')} ]`);
    return up.length != 0;
  }
  log (`outdated ${goal} did not exist`);
  return true;
}

async function update (deps, act, opts) {

  const { env, goal } = this;

  debug (`update ${goal} ${deps}`);

  env.goals[goal].deps = deps;
  if (goal !== 'Goalfile')
    deps = [ goalScript (goal) ].concat (deps);

  const srcs = deps.filter (d => ! d.startsWith ('..'));
  env.goals[goal].edges = srcs;

  if (opts !== undefined) {
    let errs = (await Promise.all (srcs.map (s => {
      return build.call (context (env, s)).then (_ => null).catch (e => ({ s, e }));
    }))).filter (e => e !== null);

    let fatals = errs.filter (e => ! new Set (opts).has (e.s));
    if (fatals.length) throw fatals[0].e;

    deps = deps.filter (d => ! new Set (errs.map (e => e.s)).has (d));

    let old = await outdated.call (this, deps);
    if (errs.length && ! old) throw errs[0].e;

    return old && act !== undefined ? await act.call (this) : undefined;
  }

  await Promise.all (srcs.map (s => build.call (context (env, s))));

  if (await outdated.call (this, deps) && act !== undefined)
    return await act.call (this);
}

async function make (goals) {

  const env = this;
  try {
    await env.run (`mkdir -p ${env.dst}`);

    env.src = (rt => r => path.join (rt, r)) (path.relative (env.dst, env.src)),
    info (`chdir ${env.dst}`);
    process.chdir (env.dst);
    delete env.dst;

    await Promise.all (goals.map (goal => build.call (context (env, goal))));
    note ('every up-to-date');
  } catch (err) {
    error (`${err.stack}`);
  }
}

function main () {
  const env = {
    dir: path.dirname, base: path.basename,

    ext: ext, exts: exts,

    trim: s => s.split ('.').slice (0, -1).join ('.'),
    split: s => s.split (/(\s+)/).filter (x => x.trim () !== '' && x !== '\\'),
    filter: (s, p) => env.split (s).map (x => x.match (p)).filter (x => x).map (x => x[0]).join (' '),

    read: read, stat: stat, run: run,

    invoke: invoke, update: update,

    goals: { }, invokes: { },

    src: '../src', dst: '../build',
    jobs: 0, maxJobs: 4, waiting: [ ]
  };

  process.on ('beforeExit', err => {
    if (err === 0) {
      let left = goals => goals.filter (g => ! env.goals[g].updated).shift ();
      let node = left (Object.keys (env.goals));
      if (node === undefined) return;

      let circle = { };
      while (! (node in circle)) {
	circle[node] = left (env.goals[node].edges);
	node = circle[node];
      }
      let path = [ node ];
      do {
	node = circle[node];
	path.push (node);
      } while (node != path[0]);

      env.goals[node].waiting.shift ().rej (new Error (`circular dependancy detected:\n  ${path.join (' => ')}`));
    }
  });

  make.call (env, [ 'tst/tst-rtld.out', 'tst/tst-live-start.out' ]);
}

main ();
