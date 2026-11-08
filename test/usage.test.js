import { test } from 'node:test';
import assert from 'node:assert/strict';
import { usage } from '../src/usage/index.js';
import { npmPackageOf, cargoManifest } from '../src/usage/imports.js';
import { requirementsGraph } from '../src/usage/graph.js';
import { fromUsage, mergeReach } from '../src/reach.js';

const root = new URL('./fixtures/usage/', import.meta.url).pathname;
const u = await usage(root);
const st = (purl) => u.components.get(purl);

test('import names: packages from specifiers, renamed crates', () => {
  assert.equal(npmPackageOf('lodash/fp'), 'lodash');
  assert.equal(npmPackageOf('@scope/pkg/sub'), '@scope/pkg');
  for (const s of ['./x', '../y', 'node:fs', 'fs', '@/lib/x', '~/a', 'https://x']) assert.equal(npmPackageOf(s), null, s);
  assert.deepEqual([...cargoManifest('json = { package = "serde_json", version = "1" }').renames], [['json', 'serde_json']]);
  assert.deepEqual([...cargoManifest('[dependencies.jsn]\npackage = "serde_json"\nversion = "1"\n').renames], [['jsn', 'serde_json']]);
});

test('npm: imported, loaded through a chain, named in a config, run by a script, never loaded', () => {
  assert.equal(st('pkg:npm/express@4.18.2').state, 'imported');
  assert.deepEqual(st('pkg:npm/qs@6.11.0').chain, ['express', 'body-parser', 'qs']);
  assert.equal(st('pkg:npm/babel-plugin-thing@1.0.0').evidence[0].how, 'named');
  assert.equal(st('pkg:npm/eslint@9.0.0').evidence[0].how, 'run by a script');
  assert.equal(st('pkg:npm/minimatch@3.0.4').state, 'loaded');
  assert.equal(st('pkg:npm/%40fontsource/inter@5.0.0').state, 'imported', 'imported by a style sheet');
  assert.equal(st('pkg:npm/normalize.css@8.0.1').state, 'imported', 'url(~package)');
  assert.deepEqual(st('pkg:npm/lodash@4.17.20'), { state: 'not_loaded', chain: ['left-pad', 'lodash'], project: 'web/package-lock.json', ecosystem: 'npm' });
});

test('Cargo, Composer, Bundler', () => {
  assert.equal(st('pkg:cargo/serde_json@1.0.108').state, 'imported', 'used under its renamed name');
  assert.deepEqual(st('pkg:cargo/openssl-sys@0.9.90').chain, ['openssl', 'openssl-sys']);
  assert.equal(st('pkg:cargo/openssl-sys@0.9.90').state, 'not_loaded');
  assert.equal(st('pkg:composer/psr/log@3.0.0').state, 'loaded');
  assert.equal(st('pkg:composer/guzzlehttp/psr7@2.4.0').state, 'not_loaded');
  assert.equal(st('pkg:composer/symfony/polyfill-mbstring@1.28.0').state, 'imported', 'autoload "files" always runs');
  assert.equal(st('pkg:gem/racc@1.7.1').state, 'loaded', 'Bundler.require loads every gem of the Gemfile');
});

test('Python: no conclusion of absence without sure import names', () => {
  assert.equal(st('pkg:pypi/requests@2.31.0').state, 'imported');
  assert.equal(st('pkg:pypi/urllib3@2.0.7').state, 'loaded');
  assert.equal(st('pkg:pypi/pyyaml@6.0.1').state, 'not_loaded', 'pyyaml installs "yaml": known');
  assert.equal(st('pkg:pypi/somelib@1.0.0').state, 'unknown');
  assert.equal(st('pkg:pypi/six@1.16.0').state, 'unknown', 'what an unsure package depends on is unsure too');
  assert.equal(requirementsGraph('flask==3.0.0\n').complete, false, 'no "# via": no graph');
  assert.equal(st('pkg:pypi/markupsafe@2.1.3').state, 'loaded');
});

test('OpenVEX: never loaded becomes a "not affected" suggestion with its chain; loaded stays open', () => {
  const finding = (purl, name, id) => ({ id, ids: [id, `CVE-${id}`], component: { type: purl.split(/[:/]/)[1], name, purl } });
  const s = fromUsage([finding('pkg:npm/lodash@4.17.20', 'lodash', 'GHSA-1'), finding('pkg:npm/qs@6.11.0', 'qs', 'GHSA-2'), finding('pkg:pypi/six@1.16.0', 'six', 'PYSEC-3')], u.components, { version: 't' });
  assert.equal(s.length, 2, 'nothing said when the analysis cannot tell');
  assert.equal(s[0].status, 'not_affected');
  assert.equal(s[0].justification, 'vulnerable_code_not_in_execute_path');
  assert.match(s[0].status_notes, /left-pad > lodash.*A suggestion to check/);
  assert.equal(s[1].status, 'under_investigation');
  assert.match(s[1].status_notes, /express > body-parser > qs \(express: web\/src\/index\.ts:1\)/);
  const doc = mergeReach([s], { product: 'pkg:generic/x', tools: ['import analysis'], now: new Date('2026-11-08T00:00:00Z') });
  assert.equal(doc.statements[0].impact_statement, s[0].status_notes);
  assert.equal(doc.tooling.includes('import analysis'), false);
});

test('the cases that must never be called "never loaded"', async () => {
  const v = await usage(new URL('./fixtures/usage2/', import.meta.url).pathname);
  const at = (purl) => v.components.get(purl);
  // Code in a folder with another lock file, lock file at the root: the whole repository is read.
  assert.equal(at('pkg:pypi/pyyaml@6.0.1').state, 'imported');
  // Also listed in a lock file that is not analysed (Pipfile.lock): no conclusion.
  assert.equal(at('pkg:pypi/beautifulsoup4@4.12.2').state, 'unknown');
  // A database driver chosen by Django's ENGINE setting, never imported.
  assert.equal(at('pkg:pypi/psycopg2-binary@2.9.9').state, 'unknown');
  // npm: an alias, "node -r dotenv/config", a tool run from the Dockerfile, an install script, code in bin/.
  assert.equal(at('pkg:npm/react-dom@17.0.2').state, 'imported');
  assert.equal(at('pkg:npm/dotenv@16.0.0').state, 'imported');
  assert.equal(at('pkg:npm/prisma@5.0.0').evidence[0].file, 'Dockerfile');
  assert.match(at('pkg:npm/sharp@0.33.0').evidence[0].how, /installed/);
  assert.equal(at('pkg:npm/cli-helper@1.0.0').evidence[0].file, 'bin/run.js');
  assert.equal(at('pkg:npm/unused-one@1.0.0').state, 'not_loaded');
  // Cargo: md-5 is used as md5; a rename in table form.
  assert.equal(at('pkg:cargo/md-5@0.10.6').state, 'imported');
  assert.equal(at('pkg:cargo/serde_json@1.0.108').state, 'imported');
  // Composer: Laravel package discovery, a class named in a config file without a leading backslash.
  assert.match(at('pkg:composer/facade/ignition@2.5.1').evidence[0].how, /Laravel/);
  assert.equal(at('pkg:composer/barryvdh/laravel-debugbar@3.9.0').state, 'imported');
  assert.equal(at('pkg:composer/league/unused@1.0.0').state, 'not_loaded');
  // A namespace in lower case (phpseclib3\\Net), a module named only in a dotted string (Django settings).
  assert.equal(at('pkg:composer/phpseclib/phpseclib@3.0.0').state, 'imported');
  assert.equal(at('pkg:pypi/django-redis@5.4.0').state, 'imported');
});

test('large files are read in linear time', async () => {
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(`${tmpdir()}/provetry-big-`);
  writeFileSync(`${dir}/package-lock.json`, JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { a: '1' } }, 'node_modules/a': { version: '1.0.0' } } }));
  writeFileSync(`${dir}/index.js`, "import 'b';\n");
  writeFileSync(`${dir}/openapi.yaml`, Array.from({ length: 60000 }, (_, i) => `  - name: item${i} "value-${i}" ref.path.x${i}`).join('\n'));
  const t = Date.now();
  const r = await usage(dir);
  assert.ok(Date.now() - t < 15000, `took ${Date.now() - t} ms`);
  assert.equal(r.components.get('pkg:npm/a@1.0.0').state, 'not_loaded');
});

test('Rust, function level: the affected functions RustSec names, in the project\'s own code', async () => {
  const { rustFunctions, functionName } = await import('../src/usage/rust.js');
  assert.equal(functionName('smallvec::SmallVec::<A>::insert_many'), 'insert_many');
  const dir = new URL('./fixtures/usage3/', import.meta.url).pathname;
  const v = await usage(dir);
  const f = (name, version, id, functions) => ({ id, ids: [id], functions, component: { type: 'cargo', name, version, purl: `pkg:cargo/${name}@${version}` } });
  const findings = [
    f('smallvec', '1.6.0', 'RUSTSEC-2021-0003', ['smallvec::SmallVec::insert_many']),
    f('memchr', '2.0.0', 'RUSTSEC-X-1', ['memchr::memchr']),
    f('bytes', '1.0.0', 'RUSTSEC-X-2', ['bytes::Bytes::slice_ref']),
    f('lazy_static', '1.4.0', 'RUSTSEC-X-3', ['lazy_static::lazy::Lazy::get']),
  ];
  const r = await rustFunctions(dir, findings, v.components);
  assert.deepEqual(r.get('RUSTSEC-2021-0003|pkg:cargo/smallvec@1.6.0'), { result: 'not_mentioned', names: ['insert_many'] });
  assert.equal(r.get('RUSTSEC-X-1|pkg:cargo/memchr@2.0.0').result, 'mentioned');
  assert.equal(r.has('RUSTSEC-X-2|pkg:cargo/bytes@1.0.0'), false, 'also loaded by hyper: its calls are not seen');
  assert.equal(r.has('RUSTSEC-X-3|pkg:cargo/lazy_static@1.4.0'), false, 'its macros expand in the code');
  const s = fromUsage(findings, v.components, { version: 't', functions: r });
  assert.equal(s.find((x) => x.purl === 'pkg:cargo/smallvec@1.6.0').status, 'not_affected');
  assert.match(s.find((x) => x.purl === 'pkg:cargo/memchr@2.0.0').status_notes, /src\/main\.rs:6 mentions memchr/);
});

test('Rust, function level: no conclusion where calls have no name in the source', async () => {
  const { rustFunctions } = await import('../src/usage/rust.js');
  const { mkdtempSync, writeFileSync, mkdirSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const make = (main, extra = {}) => {
    const dir = mkdtempSync(`${tmpdir()}/provetry-rs-`);
    mkdirSync(`${dir}/src`);
    writeFileSync(`${dir}/Cargo.toml`, '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nsv = "1"\n');
    writeFileSync(`${dir}/Cargo.lock`, 'version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "sv",\n]\n\n[[package]]\nname = "sv"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
    writeFileSync(`${dir}/src/main.rs`, main);
    for (const [k, v] of Object.entries(extra)) writeFileSync(`${dir}/${k}`, v);
    return dir;
  };
  const check = async (dir, functions) => {
    const v = await usage(dir);
    const f = { id: 'RUSTSEC-T', ids: ['RUSTSEC-T'], functions, component: { type: 'cargo', name: 'sv', version: '1.0.0', purl: 'pkg:cargo/sv@1.0.0' } };
    return (await rustFunctions(dir, [f], v.components)).get('RUSTSEC-T|pkg:cargo/sv@1.0.0')?.result ?? null;
  };
  const plain = 'use sv::Thing;\nfn main() { let t = Thing::make(); }\n';
  assert.equal(await check(make(plain), ['sv::Thing::insert_many']), 'not_mentioned');
  assert.equal(await check(make(plain), ['sv::Thing::insert_many', '<sv::Thing<A> as Drop>::drop']), null, 'a trait impl: called without its name');
  assert.equal(await check(make(plain), ['sv::Thing::index']), null, 'an operator method');
  assert.equal(await check(make('use sv::Thing;\n#[derive(Thing)]\nstruct S;\nfn main() {}\n'), ['sv::Thing::insert_many']), null, 'a derive of the crate');
  assert.equal(await check(make('#[sv::main]\nfn main() {}\n'), ['sv::rt::insert_many']), null, 'an attribute of the crate');
  assert.equal(await check(make(`${plain}include!(concat!(env!("OUT_DIR"), "/gen.rs"));\n`), ['sv::Thing::insert_many']), null, 'generated code');
  assert.equal(await check(make('use sv as other;\nfn main() { other::go!(); }\n'), ['sv::Thing::insert_many']), null, 'a macro under an alias');
  assert.equal(await check(make(`${plain}pub use sv::Thing as T;\n`), ['sv::Thing::insert_many']), null, 'a re-export');
});

test('the note the Provetry service reads as "loaded" keeps its wording', () => {
  const s = fromUsage([{ id: 'GHSA-2', ids: ['GHSA-2'], component: { type: 'npm', name: 'qs', purl: 'pkg:npm/qs@6.11.0' } }], u.components, { version: 't' });
  // provetry-repo app/src/lib/suggestions.ts matches this phrase: change both together.
  assert.match(s[0].status_notes, /import analysis of .{1,300}Whether the vulnerable function itself is called is not known/);
});

test('npm and PyPI, function level from the vulnerable-functions data', async () => {
  const { loadFunctionData, packageFunctions } = await import('../src/usage/functions.js');
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const make = (code) => {
    const dir = mkdtempSync(`${tmpdir()}/provetry-pvf-`);
    writeFileSync(`${dir}/package.json`, '{"dependencies":{"flat":"5.0.0"}}');
    writeFileSync(`${dir}/package-lock.json`, JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { flat: '5.0.0' } }, 'node_modules/flat': { version: '5.0.0' } } }));
    writeFileSync(`${dir}/index.js`, code);
    return dir;
  };
  const records = {
    'GHSA-2j2x-2gpw-g8fm': [{ id: 'GHSA-2j2x-2gpw-g8fm', ecosystem: 'npm', package: 'flat', entryPoints: ['unflatten'], methods: [], whole: false }],
    'GHSA-xxxx-xxxx-xxxx': [{ id: 'GHSA-xxxx-xxxx-xxxx', ecosystem: 'npm', package: 'flat', entryPoints: ['flatten'], methods: ['Obj.run'], whole: false }],
  };
  const urls = [];
  const ctx = { fetchJson: async (url) => { urls.push(url); const id = url.split('/').pop().replace('.json', ''); return records[id] ? { status: 200, json: records[id] } : { status: 404, json: null }; } };
  const finding = (id) => ({ id, ids: [id], component: { type: 'npm', name: 'flat', version: '5.0.0', purl: 'pkg:npm/flat@5.0.0' } });
  const findings = [finding('GHSA-2j2x-2gpw-g8fm'), finding('GHSA-xxxx-xxxx-xxxx')];
  const data = await loadFunctionData(ctx, findings, { baseUrl: 'https://example.test/data' });
  assert.equal(data.size, 2);
  assert.ok(urls[0].startsWith('https://example.test/data/GHSA-'));
  const run = async (code) => { const dir = make(code); return packageFunctions(dir, findings, (await usage(dir)).components, data); };
  let r = await run("const flatten = require('flat');\nflatten({ a: 1 });\n");
  assert.deepEqual(r.get('GHSA-2j2x-2gpw-g8fm|pkg:npm/flat@5.0.0').result, 'not_mentioned');
  assert.equal(r.has('GHSA-xxxx-xxxx-xxxx|pkg:npm/flat@5.0.0'), false, 'methods lead to it: no conclusion');
  r = await run("const { unflatten } = require('flat');\nunflatten({ 'a.b': 1 });\n");
  assert.equal(r.get('GHSA-2j2x-2gpw-g8fm|pkg:npm/flat@5.0.0').result, 'mentioned');
  const s = fromUsage([finding('GHSA-2j2x-2gpw-g8fm')], (await usage(make("require('flat')({})\n"))).components, { version: 't', functions: new Map([['GHSA-2j2x-2gpw-g8fm|pkg:npm/flat@5.0.0', { result: 'not_mentioned', names: ['unflatten'], source: 'data' }]]) });
  assert.equal(s[0].status, 'not_affected');
  assert.match(s[0].status_notes, /lead to the fixed code \(data\): unflatten/);
});
