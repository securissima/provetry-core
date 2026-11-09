import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pyCall, narrowest, jellyPattern, confirmCalls, jellyCalls } from '../src/usage/calls.js';
import { fromUsage } from '../src/reach.js';

const JELLY = fileURLToPath(new URL('../node_modules/@cs-au-dk/jelly/lib/main.js', import.meta.url));

test('Python: a call of the package function, through its import', () => {
  const at = (src, names = ['load']) => pyCall(src, ['yaml'], names)?.line ?? null;
  assert.equal(at('import yaml\nx = yaml.load(s)\n'), 2);
  assert.equal(at('import yaml as y\ndef f():\n    return y.load(s)\n'), 3);
  assert.equal(at('from yaml import load as l\nl(s)\n'), 2);
  assert.equal(at('from yaml import (\n  dump,\n  load,\n)\n\nload(s)\n'), 6, 'a multi-line import');
  assert.equal(at('import yaml.constructor\nyaml.constructor.load(s)\n'), 2);
  assert.equal(at('import os, yaml\nyaml.load(s)\n'), 2);
});

test('Python: no call claimed where the name is not the package function', () => {
  const at = (src) => pyCall(src, ['yaml'], ['load']);
  assert.equal(at('from yaml import load\ndef load(s): pass\nload(s)\n'), null, 'defined again');
  assert.equal(at('from yaml import load\nload = other\nload(s)\n'), null, 'assigned again');
  assert.equal(at('from yaml import load\nfor load in xs: load(s)\n'), null, 'a loop variable');
  assert.equal(at('from yaml import load\ndef f(load):\n    return load(s)\n'), null, 'a parameter');
  assert.equal(at('import yaml\n# yaml.load(s)\nx = "yaml.load(s)"\n'), null, 'comments and strings');
  assert.equal(at('from yaml import *\nload(s)\n'), null, 'a star import');
  assert.equal(at('import json\njson.load(f)\n'), null, 'another module');
  assert.equal(at('from yaml import Loader\nLoader.load(s)\n'), null, 'a class of the package: its methods may share the name');
  assert.equal(at('import yaml\nmyyaml.load(s)\nx.yaml.load(s)\n'), null, 'another object');
  assert.equal(at('from yaml import load\nfrom json import load\nload(f)\n'), null, 'imported again from another module');
  assert.equal(at('from yaml import load\ndef f():\n    from json import load\n    return load(f)\n'), null, 'imported again inside a function');
  assert.equal(at('from yaml import load\nfrom json import (\n  load,\n)\nload(s)\n'), null, 'imported again, in parentheses');
  assert.equal(at('from yaml import load\nload: Callable = other\nload(s)\n'), null, 'an annotated assignment');
  assert.equal(at('from yaml import load\nif (load := other): load(s)\n'), null, 'a walrus');
  assert.equal(at('from yaml import load\nload += 1\nload(s)\n'), null, 'an augmented assignment');
  assert.equal(at('from yaml import load\nmatch x:\n    case load:\n        load(s)\n'), null, 'a case capture');
  assert.equal(at('import yaml\nyaml.YAMLObject.load(s)\n'), null, 'a method of a class, through the module');
  assert.equal(pyCall('import google.cloud.storage\ngoogle.auth.load(x)\n', ['google.cloud.storage'], ['load']), null, 'another package of a namespace');
});

test('Jelly helpers: the pattern and the narrowest place', () => {
  assert.equal(jellyPattern('@a/b', ['x']), 'call {<@a/b>,<@a/b/**>}.x');
  assert.equal(jellyPattern('x', ['a b']), null);
  assert.equal(jellyPattern('x y', ['a']), null);
  assert.deepEqual(narrowest(['/r/a.js:1:1:5:1', '/r/a.js:3:25:3:29', '/r/node_modules/z.js:1:1:1:2', '/elsewhere/b.js:1:1:1:2'], '/r'), { file: 'a.js', line: 3 });
});

const project = (files) => {
  const dir = mkdtempSync(join(tmpdir(), 'provetry-calls-'));
  writeFileSync(join(dir, 'package.json'), '{"name":"app","dependencies":{"flat":"5.0.0"}}');
  for (const [p, t] of Object.entries(files)) { mkdirSync(join(dir, p, '..'), { recursive: true }); writeFileSync(join(dir, p), t); }
  return dir;
};

test('Jelly finds the call through an alias, and not a method of the same name elsewhere', async () => {
  const dir = project({
    'src/a.js': "const { unflatten: u } = require('flat');\nfunction go(x) { return u(x); }\nmodule.exports = { go };\n",
    'src/b.mjs': "import flat from 'flat';\nconst mine = { unflatten(x) { return x; } };\nexport const run = (x) => mine.unflatten(flat(x));\n",
  });
  const r = await jellyCalls(dir, [{ key: 'k', pkg: 'flat', names: ['unflatten'] }], { jelly: JELLY, timeout: 120_000 });
  assert.deepEqual(r.get('k'), { file: 'src/a.js', line: 2, names: ['unflatten'] });
  const only = project({ 'src/b.mjs': "import flat from 'flat';\nconst mine = { unflatten(x) { return x; } };\nexport const run = (x) => mine.unflatten(flat(x));\n" });
  assert.equal((await jellyCalls(only, [{ key: 'k', pkg: 'flat', names: ['unflatten'] }], { jelly: JELLY, timeout: 120_000 })).has('k'), false);
});

test('Jelly: a method of the same name on what the package returns or creates is not its function', async () => {
  const dir = project({
    'src/a.js': "const flat = require('flat');\nmodule.exports = (x) => flat({ a: 1 }).unflatten(x);\n",
    'src/b.js': "const lib = require('flat');\nmodule.exports = (x) => new lib.Thing().unflatten(x);\n",
    'src/c.mjs': "import * as F from 'flat';\nexport default (x) => F.unflatten(x);\n",
  });
  const r = await jellyCalls(dir, [{ key: 'k', pkg: 'flat', names: ['unflatten'] }], { jelly: JELLY, timeout: 120_000 });
  assert.deepEqual(r.get('k'), { file: 'src/c.mjs', line: 2, names: ['unflatten'] });
});

test('the note of a found call is the one the Provetry service reads', () => {
  // Same expression as the app (app/src/lib/suggestions.ts, CALLS).
  const CALLS = /import analysis of [\s\S]{1,2000}?the call analysis \([^()]{1,60}\) finds a call of /;
  const npm = { id: 'GHSA-2j2x-2gpw-g8fm', ids: ['GHSA-2j2x-2gpw-g8fm'], component: { type: 'npm', name: '@a-very-long-scope/with-a-long-package-name', version: '5.0.0', purl: 'pkg:npm/%40a-very-long-scope/with-a-long-package-name@5.0.0' } };
  const functions = new Map([[`${npm.id}|${npm.component.purl}`, { result: 'mentioned', name: 'x', file: 'a.js', line: 1, source: 's', called: { file: 'b.js', line: 2, name: 'x', by: 'Jelly call graph' } }]]);
  const found = new Map([[npm.component.purl, { state: 'imported', project: `${'deep/'.repeat(45)}package-lock.json`, evidence: [{ file: 'a.js', line: 1, how: 'imported' }] }]]);
  const [st] = fromUsage([npm], found, { functions });
  assert.match(st.status_notes, CALLS);
  assert.deepEqual(st.evidence.mentioned, { file: 'a.js', line: 1 });
  assert.doesNotMatch(st.status_notes, /likely|proves?|certain/);
});

test('a failing call analysis changes nothing', async () => {
  const dir = project({ 'a.js': "require('flat').unflatten(1);\n" });
  assert.equal((await jellyCalls(dir, [{ key: 'k', pkg: 'flat', names: ['unflatten'] }], { jelly: '/nonexistent/jelly.js', timeout: 20_000 })).size, 0);
  // End to end: the mention stays, and reach says "mentioned".
  const f = { id: 'GHSA-2j2x-2gpw-g8fm', ids: ['GHSA-2j2x-2gpw-g8fm'], component: { type: 'npm', name: 'flat', version: '5.0.0', purl: 'pkg:npm/flat@5.0.0' } };
  const key = `${f.id}|${f.component.purl}`;
  const functions = new Map([[key, { result: 'mentioned', name: 'unflatten', file: 'a.js', line: 1, source: 's' }]]);
  const prev = process.env.PROVETRY_JELLY;
  process.env.PROVETRY_JELLY = '/nonexistent/jelly.js';
  try { await confirmCalls(dir, [f], functions, new Map([[key, { entryPoints: ['unflatten'] }]]), { timeout: 20_000 }); } finally { if (prev === undefined) delete process.env.PROVETRY_JELLY; else process.env.PROVETRY_JELLY = prev; }
  const [st] = fromUsage([f], new Map([[f.component.purl, { state: 'imported', project: 'package-lock.json', evidence: [{ file: 'a.js', line: 1, how: 'imported' }] }]]), { functions });
  assert.equal(st.evidence.state, 'mentioned');
});

test('the child gets no secret of the pipeline', async () => {
  const dir = project({ 'a.js': '' });
  const spy = join(dir, 'spy.js');
  writeFileSync(spy, "require('fs').writeFileSync(process.argv.at(-1) + '/env.json', JSON.stringify(process.env));\n");
  const prev = { k: process.env.PROVETRY_API_KEY, o: process.env.NODE_OPTIONS };
  process.env.PROVETRY_API_KEY = 'pk_secret'; process.env.NODE_OPTIONS = '--use-system-ca';
  try { await jellyCalls(dir, [{ key: 'k', pkg: 'flat', names: ['unflatten'] }], { jelly: spy, timeout: 20_000 }); } finally {
    if (prev.k === undefined) delete process.env.PROVETRY_API_KEY; else process.env.PROVETRY_API_KEY = prev.k;
    if (prev.o === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = prev.o;
  }
  const env = JSON.parse((await import('node:fs')).readFileSync(join(dir, 'env.json'), 'utf8'));
  assert.equal(env.PROVETRY_API_KEY, undefined);
  assert.match(env.NODE_OPTIONS, /--use-system-ca .*--max-old-space-size/);
});

test('confirmCalls adds the call to a mentioned result, and reach says so; a mention without a call stays as it was', async () => {
  const dir = project({ 'src/a.js': "const f = require('flat');\nmodule.exports = (x) => f.unflatten(x);\n", 'tool.py': 'import yaml\nyaml.load(s)\n' });
  const npm = { id: 'GHSA-2j2x-2gpw-g8fm', ids: ['GHSA-2j2x-2gpw-g8fm'], component: { type: 'npm', name: 'flat', version: '5.0.0', purl: 'pkg:npm/flat@5.0.0' } };
  const py = { id: 'GHSA-8q59-q68h-6hv4', ids: ['GHSA-8q59-q68h-6hv4'], component: { type: 'pypi', name: 'PyYAML', version: '5.3', purl: 'pkg:pypi/pyyaml@5.3' } };
  const other = { id: 'GHSA-aaaa-bbbb-cccc', ids: ['GHSA-aaaa-bbbb-cccc'], component: { type: 'pypi', name: 'PyYAML', version: '5.3', purl: 'pkg:pypi/pyyaml@5.3' } };
  const key = (f) => `${f.id}|${f.component.purl}`;
  const functions = new Map([
    [key(npm), { result: 'mentioned', name: 'unflatten', file: 'src/a.js', line: 2, source: 's' }],
    [key(py), { result: 'mentioned', name: 'load', file: 'tool.py', line: 2, source: 's' }],
    [key(other), { result: 'mentioned', name: 'full_load', file: 'tool.py', line: 2, source: 's' }],
  ]);
  const data = new Map([[key(npm), { entryPoints: ['unflatten'] }], [key(py), { entryPoints: ['load'] }], [key(other), { entryPoints: ['full_load'] }]]);
  const prev = process.env.PROVETRY_JELLY;
  process.env.PROVETRY_JELLY = JELLY;
  try { await confirmCalls(dir, [npm, py, other], functions, data, { timeout: 120_000 }); } finally { if (prev === undefined) delete process.env.PROVETRY_JELLY; else process.env.PROVETRY_JELLY = prev; }
  assert.deepEqual(functions.get(key(npm)).called, { file: 'src/a.js', line: 2, name: 'unflatten', by: 'Jelly call graph' });
  assert.deepEqual(functions.get(key(py)).called, { file: 'tool.py', line: 2, name: 'load', by: 'Python import and call reading' });
  assert.equal(functions.get(key(other)).called, undefined);
  const found = new Map([[npm.component.purl, { state: 'imported', project: 'package-lock.json', evidence: [{ file: 'src/a.js', line: 1, how: 'imported' }] }]]);
  const [st] = fromUsage([npm], found, { functions });
  assert.equal(st.status, 'under_investigation');
  assert.equal(st.evidence.state, 'called');
  assert.match(st.status_notes, /finds a call of flat's unflatten at src\/a\.js:2/);
});
