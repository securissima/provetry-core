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
});

test('Jelly helpers: the pattern and the narrowest place', () => {
  assert.equal(jellyPattern('@a/b', ['x']), 'call {<@a/b>,<@a/b/**>}**.x');
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

test('a failing call analysis changes nothing', async () => {
  const dir = project({ 'a.js': "require('flat').unflatten(1);\n" });
  assert.equal((await jellyCalls(dir, [{ key: 'k', pkg: 'flat', names: ['unflatten'] }], { jelly: '/nonexistent/jelly.js', timeout: 20_000 })).size, 0);
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
