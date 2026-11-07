import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { collect, parseNpmLock, parseYarnLock, parsePnpmLock, parseRequirements, parseTomlPackages, parseGoMod, parseComposerLock, parseGemfileLock, parseNugetLock, npmIntegrity } from '../src/lockfiles/index.js';
import { makePurl, parsePurl } from '../src/purl.js';

const fx = (p) => readFileSync(fileURLToPath(new URL(`fixtures/proj/${p}`, import.meta.url)), 'utf8');
const byName = (list) => Object.fromEntries(list.map((c) => [c.name, c]));

test('purls follow the spec for scoped npm, PyPI, Go and Composer names', () => {
  assert.equal(makePurl('npm', '@babel/core', '7.24.0'), 'pkg:npm/%40babel/core@7.24.0');
  assert.equal(makePurl('pypi', 'PyYAML', '6.0.1'), 'pkg:pypi/pyyaml@6.0.1');
  assert.equal(makePurl('pypi', 'zope.interface', '6.0'), 'pkg:pypi/zope-interface@6.0');
  assert.equal(makePurl('golang', 'github.com/gin-gonic/gin', 'v1.9.0'), 'pkg:golang/github.com/gin-gonic/gin@v1.9.0');
  assert.equal(makePurl('composer', 'Symfony/HTTP-Kernel', '5.4.20'), 'pkg:composer/symfony/http-kernel@5.4.20');
  assert.deepEqual(parsePurl('pkg:npm/%40babel/core@7.24.0'), { type: 'npm', namespace: '@babel', name: 'core', version: '7.24.0' });
});

test('npm v3 lock: versions, nested copies, scopes, direct dependencies, hashes, no workspace links', () => {
  const c = parseNpmLock(fx('web/package-lock.json'));
  const n = byName(c);
  assert.deepEqual(Object.keys(n).sort(), ['@babel/core', 'debug', 'express', 'fsevents', 'vitest']);
  assert.equal(n.express.direct, true);
  assert.equal(n.debug.direct, false);
  assert.equal(n.vitest.scope, 'dev');
  assert.equal(n.fsevents.scope, 'optional');
  assert.equal(n.express.hashes[0].alg, 'SHA-512');
  assert.equal(n.express.hashes[0].content.length, 128);
});

test('npm v1 lock (nested dependencies)', () => {
  const c = parseNpmLock(JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0', dev: true } } }, l: { version: 'file:../l' } } }));
  assert.deepEqual(c.map((x) => `${x.name}@${x.version}:${x.scope}:${x.direct}`), ['a@1.0.0:required:true', 'b@2.0.0:dev:false']);
});

test('yarn v1 lock, including scoped packages', () => {
  const n = byName(parseYarnLock(fx('web/yarn.lock')));
  assert.equal(n['@babel/core'].version, '7.24.0');
  assert.equal(n.lodash.version, '4.17.20');
});

test('yarn Berry lock: npm: protocol, aliases and workspaces', () => {
  const text = `__metadata:\n  version: 6\n\n"left-pad@npm:^1.3.0":\n  version: 1.3.0\n  resolution: "left-pad@npm:1.3.0"\n\n"my-alias@npm:lodash@^4.17.21":\n  version: 4.17.21\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n`;
  const n = byName(parseYarnLock(text));
  assert.equal(n['left-pad'].version, '1.3.0');
  assert.equal(n.lodash.version, '4.17.21');
  assert.equal(n.app, undefined);
});

test('pnpm v9 lock: packages, scoped names, dev dependencies of the root', () => {
  const n = byName(parsePnpmLock(fx('web/pnpm-lock.yaml')));
  assert.equal(n.axios.version, '1.6.0');
  assert.equal(n['@types/node'].version, '20.12.7');
  assert.equal(n.typescript.scope, 'dev');
  assert.equal(n.axios.scope, 'required');
  assert.equal(n.axios.hashes.length, 1);
});

test('pnpm v6 lock: leading slash and peer suffixes', () => {
  const text = `lockfileVersion: '6.0'\n\npackages:\n\n  /react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-AAAA}\n    dev: true\n`;
  const [c] = parsePnpmLock(text);
  assert.equal(c.name, 'react-dom');
  assert.equal(c.version, '18.2.0');
  assert.equal(c.scope, 'dev');
});

test('requirements.txt: only pinned versions, extras and hashes', () => {
  const n = byName(parseRequirements(fx('api/requirements.txt')));
  assert.deepEqual(Object.keys(n).sort(), ['Django', 'PyYAML', 'requests']);
  assert.equal(n.Django.hashes[0].alg, 'SHA-256');
  assert.equal(n.PyYAML.purl, 'pkg:pypi/pyyaml@6.0.1');
});

test('poetry.lock and Cargo.lock', () => {
  const p = byName(parseTomlPackages(fx('api/poetry.lock'), 'pypi'));
  assert.equal(p.Jinja2.version, '3.1.2');
  assert.equal(p.pytest.scope, 'dev');
  const c = parseTomlPackages(fx('svc/Cargo.lock'), 'cargo');
  assert.deepEqual(c.map((x) => x.purl), ['pkg:cargo/openssl@0.10.55']);
});

test('uv.lock skips the project itself', () => {
  const text = `[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n\n[[package]]\nname = "urllib3"\nversion = "2.0.0"\nsource = { registry = "https://pypi.org/simple" }\n`;
  assert.deepEqual(parseTomlPackages(text, 'pypi').map((c) => c.name), ['urllib3']);
});

test('go.mod: direct, indirect and replace', () => {
  const n = byName(parseGoMod(fx('svc/go.mod')));
  assert.equal(n['github.com/gin-gonic/gin'].direct, true);
  assert.equal(n['golang.org/x/net'].direct, false);
  assert.equal(n['github.com/new/pkg'].version, 'v1.2.0');
  assert.equal(n['github.com/old/pkg'], undefined);
});

test('composer.lock, Gemfile.lock and packages.lock.json', () => {
  const comp = byName(parseComposerLock(fx('svc/composer.lock')));
  assert.equal(comp['Symfony/HTTP-Kernel'].version, '5.4.20');
  assert.equal(comp['phpunit/phpunit'].scope, 'dev');
  assert.equal(comp['foo/bar'], undefined);
  const gems = byName(parseGemfileLock(fx('svc/Gemfile.lock')));
  assert.deepEqual(Object.keys(gems).sort(), ['nokogiri', 'racc', 'rails']);
  assert.equal(gems.nokogiri.version, '1.15.4');
  const nu = parseNugetLock(fx('svc/packages.lock.json'));
  assert.deepEqual(nu.map((x) => [x.purl, x.direct]), [['pkg:nuget/Newtonsoft.Json@13.0.1', true]]);
});

test('collect walks a project and merges duplicates across files', async () => {
  const root = fileURLToPath(new URL('fixtures/proj', import.meta.url));
  const { components, files, errors } = await collect(root);
  assert.deepEqual(errors, []);
  assert.equal(files.length, 10);
  const babel = components.filter((c) => c.purl === 'pkg:npm/%40babel/core@7.24.0');
  assert.equal(babel.length, 1);
  assert.deepEqual(babel[0].sources.sort(), ['web/package-lock.json', 'web/yarn.lock']);
});

test('npm integrity decoding ignores junk', () => {
  assert.deepEqual(npmIntegrity('nope'), []);
  assert.equal(npmIntegrity('sha1-AAAA')[0].alg, 'SHA-1');
});
