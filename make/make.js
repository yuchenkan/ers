'use strict';

const util = require ('util');
const assert = require ('assert');
const path = require ('path');
const fs = require ('fs');
const os = require ('os');

const fstat = util.promisify (fs.fstat);
const open = util.promisify (fs.open);
const close = util.promisify (fs.close);
const readFile = util.promisify (fs.readFile);

const child_process = require ('child_process');
const exec = util.promisify (child_process.exec);

const AsyncFunction = Object.getPrototypeOf (async function () { }).constructor;

let verbose = 0;
const debug = msg => {
  if (verbose > 1) console.log (`[debug] ${msg}`);
}

const info = msg => console.log ('\x1b[33m%s\x1b[0m', `[info] ${msg}`);
const note = msg => console.log ('\x1b[32m%s\x1b[0m', `[note] ${msg}`);
const fatal = msg => console.log ('\x1b[31m%s\x1b[0m', `[fatal] ${msg}`);

async function read (file, opt) {

  try { return await readFile (file, 'utf8'); }
  catch (err) {
    if (opt && err.code === 'ENOENT') return null;
    throw err;
  }
}

async function ctime (file) {

  try { var fd = await open (file, 'r'); }
  catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }

  try { return (await fstat (fd)).ctimeMs; }
  finally { await close (fd); }
}

const def = (v, d, p) => v ? (p ? p (v) : v) : d;
const norm = p => path.normalize (path.relative ('.', p));
const context = (env, goal) => ({ update: env.update, invoke: env.invoke, env, goal });

const wait = async list => await new Promise ((res, rej) => list.push ({ res, rej }));
const wake = (list, all) => all ? list.map (x => x.res ()) : list.shift ().res ();

async function run (cmd, quiet) {

  const env = this;

  if (env.jobs === env.maxJobs) await wait (env.waiting);
  else ++env.jobs;

  if (! quiet || verbose > 0) info (cmd);

  try {
    let { stdout } = await exec (cmd);
    if (! quiet) process.stdout.write (stdout);
    return stdout;
  } finally {
    if (env.waiting.length) wake (env.waiting, false);
    else --env.jobs;
  }
}

const visit = async (c, k) => {

  if (! (k in c)) {
    c[k] = { waiting: [ ] };
    return c[k];
  }

  if (c[k].waiting) await wait (c[k].waiting);
  return null;
}

const finish = v => {
  const w = v.waiting;
  delete v.waiting;
  wake (w, true);
}

async function collect () {

  const { env, goal } = this;

  const infos = env.infos;
  const first = await visit (infos, goal);
  if (! first) return;
  debug (`collect ${goal}`);

  if (env.phony.has (goal)) {
    debug ('collect phony goal changed');
    delete env.stats[goal];
  } else {
    const stat = env.stats[goal];
    const deps = stat.deps;
    await Promise.all (deps.map (d => collect.call (context (env, d))));
    if (env.phony.has (goal)) {
    } else if (! deps.every (d => d in env.stats && stat.ctime >= env.stats[d].ctime)) {
      debug ('collect dependend goal changed');
      delete env.stats[goal];
    } else if (stat.src
	       && (stat.src !== env.src (goal)
		   || def (await ctime (stat.src), await ctime (goal), t => t >= stat.ctime))) {
      debug ('collect source goal changed');
      delete env.stats[goal];
    } else env.goals[goal] = { };
  }
/*
if (goal === 'live/tst/tst-sig-mask-async-ut.out')
console.log (deps, deps.every (d => d in env.stats), goal in env.stats);
if (new Set ([ 'tst/tst-common-start.S.o', 'all' ]).has (goal))
console.log (goal, stat, goal in env.stats);
*/
  if (! (goal in env.stats)) await env.run (`rm -f ${goal}`, true);

  debug (`collect ${goal} ${goal in env.stats}`);
  finish (first);
}

async function invoke (script, args) {
  const { env, goal } = this;
  script = norm (script);
  if (args === undefined) args = { };
  debug (`invoke ${script} ${goal} [ ${Object.keys (args).join (', ')} ]`);

  await this.update ([ script ]);

  const keys = Object.keys (args);
  assert (keys.every (k => k.match (',') === null));
  const name = `${script}//${keys}`;

  try {

    const first = await visit (env.funcs, name);

    if (first) {
      let decl = [ null, 'env', 'goal' ].concat (keys).concat (await read (script));
      first.fn = new (AsyncFunction.bind.apply (AsyncFunction, decl));
      finish (first);
    }

    return await env.funcs[name].fn.apply (this, [ env, goal ].concat (keys.map (k => args[k])));

  } catch (err) {
    if (script !== 'Goalfile')
      err.stack = `    by ${script}\n${err.stack}`;
    throw err;
  }
}

async function build () {

  const { env, goal } = this;

  debug (`build ${goal}`);

  const goals = env.goals;

  const first = await visit (goals, goal);
  if (! first) return;

  first.deps = new Set ();
  try {

    if (verbose > 0) note (`build ${goal}`);

    await env.mkdir (goal);
    if (goal === 'Goalfile' || await this.invoke ('Goalfile') === false) {
      var src = env.src (goal);
      if (await ctime (src)) await env.run (`cp ${src} ${goal} && chmod a-w ${goal}`, true);
    }

    env.stats[goal] = { deps: Array.from (first.deps), ctime: env.ctime, src };
    env.save ();

  } catch (err) {
    err.stack = `  when build ${goal}\n${err.stack}`;
    throw err;
  }
  finish (first);
}

async function update (deps) {

  const { env, goal } = this;

  deps = Array.from (new Set (deps.map (d => norm (d))));
  debug (`update ${goal} ${deps}`);

  assert (deps.every (d => ! d.startsWith ('..')));

  if (goal) env.goals[goal].edges = deps;

  await Promise.all (deps.map (d => build.call (context (env, d))));

  if (goal) deps.forEach (d => env.goals[goal].deps.add (d));
}

async function mkdir (file) {
  const env = this;

  file = norm (file);
  assert (! file.startsWith ('..'));
  const dir = env.dir (file);

  /* XXX: optimize mkdir a/b when a/b/c is done */
  let first = await visit (env.dirs, dir);
  if (! first) return;

  if (dir !== '.') env.run (`mkdir -p ${dir}`, true);

  finish (first);
}

function main () {

  let maxJobs = 1;
  const phony = [ ];
  const args = [ ];
  process.argv.shift ();
  process.argv.shift ();
  try {
    while (process.argv.length) {
      let a = process.argv.shift ();
      if (a === '-v')
	verbose = isNaN (Number (process.argv[0])) ? 1 : Number (process.argv.shift ());
      else if (a === '-j') maxJobs = Number (process.argv.shift ());
      else if (a === '-p') {
	assert (process.argv.length);
	phony.push (process.argv.shift ());
      } else {
	assert (a[0] !== '-');
        args.push (a);
      }
    }
    assert (! isNaN (maxJobs));
    if (maxJobs > 2 * os.cpus ().length) maxJobs = 2 * os.cpus ().length;
    assert (args.length >= 3);
  } catch (err) {
    fatal ('usage: node make.js [-v N -j N -p phony] src dst goal ...');
    debug (err.stack);
    process.exit (1);
  }

  const src = norm (args.shift ());
  const dst = norm (args.shift ());

  try {
    assert (path.relative (src, dst).startsWith ('..'));
    assert (path.relative (dst, src).startsWith ('..'));
  } catch (err) {
    fatal ('do not nest src dst dir');
    debug (err.stack);
    process.exit (1);
  }

  const env = {
    def: def,

    dir: path.dirname, base: path.basename, join: path.join,

    mkdir, dirs: { },

    ext: (f, e) => f.endsWith (`.${e}`),
    exts: (f, es) => ! es.every (e => ! env.ext (f, e)),

    trim: s => s.split ('.').slice (0, -1).join ('.'),
    split: s => s.split (/(\s+)/).filter (x => x.trim () !== '' && x !== '\\'),
    filter: (s, p) => env.split (s).map (x => x.match (p)).map (x => x === null ? '' : x[0]).join (' '),
    diff: (a, b) => a.filter (x => ! b.includes (x)),

    read, run,

    invoke, update,

    infos: { }, goals: { }, funcs: { },

    src, dst, phony,
    jobs: 0, maxJobs, waiting: [ ]
  };

  const circular = () => {
    const goals = env.goals;
    const left = gs => gs.filter (g => goals[g].waiting && goals[g].waiting.length).shift ();
    let node = left (Object.keys (goals));
    assert (node);

    const circle = { };
    while (! (node in circle)) {
      circle[node] = left (goals[node].edges);
      node = circle[node];
    }
    const link = [ node ];
    do {
      node = circle[node];
      link.push (node);
    } while (node !== link[0]);

    goals[node].waiting.shift ().rej (new Error (`circular dependancy detected:\n  ${link.join (' => ')}`));
  };

  const make = async goals => {

    await env.run (`mkdir -p ${env.dst}`, true);
    env.src = (rt => r => path.join (rt, r)) (path.relative (env.dst, env.src)),
    info (`cd ${env.dst}`);
    process.chdir (env.dst);

    if (await ctime ('.goal-lock')) {
      fatal ('locked');
      process.exit (1);
    }
    await env.run ('touch .goal-lock');
    process.on ('SIGINT', () => {
      child_process.execSync ('rm .goal-lock');
      process.exit (1);
    });

    env.phony = new Set (env.phony.map (p => norm (p)));

    note ('collecting goal stats...');
    env.stats = def (await read ('.goal-stats', true), { }, JSON.parse);
    await Promise.all (Object.keys (env.stats).map (g => collect.call (context (env, g))));

    await env.run ('touch .goal-ctime', true);
    env.ctime = await ctime ('.goal-ctime');
    env.save = () => fs.writeFileSync ('.goal-stats', JSON.stringify (env.stats));

    process.on ('beforeExit', circular);

    try {
      await update.call (context (env, null), goals);
      note ('every up-to-date');
      process.removeListener ('beforeExit', circular);
    } finally { await exec ('rm .goal-lock'); }
  };

  make (args).catch (err => {
    fatal (`dst: ${env.dst}\n${err.stack}`);
    process.exit (1);
  });
}

main ();
