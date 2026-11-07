import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collect, parsePnpmLock, parseGoMod, parseGemfileLock, parseRequirements, readLockFile } from '../src/lockfiles/index.js';
import { cargoNames, pyprojectNames } from '../src/lockfiles/manifests.js';
import { toCycloneDx, toSpdx } from '../src/sbom/write.js';
import { readSbom } from '../src/sbom/read.js';
import { readVex, vexFor } from '../src/vex.js';
import { reportingClock } from '../src/clock.js';

const root = new URL('./fixtures/proj', import.meta.url).pathname;
const cli = new URL('../src/cli.js', import.meta.url).pathname;
const byName = (l) => Object.fromEntries(l.map((c) => [c.name, c]));

test('pnpm: direct dependencies from the importers, dev only for the exact version listed', () => {
  const text = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      debug:
        specifier: ^4
        version: 4.3.4(supports-color@8.1.1)
    devDependencies:
      debug2:
        specifier: ^2
        version: 2.6.9
      typescript:
        specifier: ^5
        version: 5.4.5

packages:

  debug@4.3.4:
    resolution: {integrity: sha512-AAAA}

  debug@2.6.9:
    resolution: {integrity: sha512-AAAA}

  debug2@2.6.9:
    resolution: {integrity: sha512-AAAA}

  typescript@5.4.5:
    resolution: {integrity: sha512-AAAA}
`;
  const c = parsePnpmLock(text);
  const get = (n, v) => c.find((x) => x.name === n && x.version === v);
  assert.equal(get('debug', '4.3.4').direct, true);
  assert.equal(get('debug', '4.3.4').scope, 'required');
  assert.equal(get('debug', '2.6.9').scope, 'required', 'another version of a name is not made dev');
  assert.equal(get('debug', '2.6.9').direct, false);
  assert.equal(get('typescript', '5.4.5').scope, 'dev');
  assert.throws(() => parsePnpmLock(`lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-AAAA}\n`), /not supported/);
  const v6 = parsePnpmLock(`lockfileVersion: '6.0'\n\ndependencies:\n  lodash:\n    specifier: ^4\n    version: 4.17.21\n  local:\n    specifier: link:../local\n    version: link:../local\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: sha512-AAAA}\n    dev: false\n`);
  assert.equal(v6[0].direct, true);
});

test('pnpm v9: snapshots are not importers, and what only dev tools pull in is dev', () => {
  const text = `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      foo:
        specifier: ^1
        version: 1.0.0
    devDependencies:
      jest:
        specifier: ^29
        version: 29.0.0

packages:

  foo@1.0.0:
    resolution: {integrity: sha512-AAAA}

  bar@1.0.0:
    resolution: {integrity: sha512-AAAA}

  jest@29.0.0:
    resolution: {integrity: sha512-AAAA}

  jestdep@1.0.0:
    resolution: {integrity: sha512-AAAA}

snapshots:

  foo@1.0.0:
    dependencies:
      bar: 1.0.0

  bar@1.0.0: {}

  jest@29.0.0:
    dependencies:
      jestdep: 1.0.0
      bar: 1.0.0

  jestdep@1.0.0: {}
`;
  const n = byName(parsePnpmLock(text));
  assert.deepEqual(Object.values(n).map((c) => `${c.name}:${c.direct}:${c.scope}`).sort(), ['bar:false:required', 'foo:true:required', 'jest:true:dev', 'jestdep:false:dev']);
});

test('manifests give direct dependencies to lock files that do not record them', async () => {
  const y = await readLockFile(join(root, 'web/yarn.lock'), root);
  assert.equal(byName(y)['@babel/core'].direct, true);
  assert.equal(byName(y).lodash.direct, false);
  const { components } = await collect(root);
  const bom = toCycloneDx({ name: 'demo' }, components);
  assert.ok(bom.dependencies[0].dependsOn.includes('pkg:npm/%40babel/core@7.24.0'));
  assert.ok(!bom.dependencies[0].dependsOn.includes('pkg:npm/lodash@4.17.20'));
  const spdx = toSpdx({ name: 'demo' }, components);
  const dependsOn = spdx.relationships.filter((r) => r.relationshipType === 'DEPENDS_ON').length;
  assert.equal(dependsOn, components.filter((c) => c.direct && c.scope !== 'dev').length);
  assert.equal(toCycloneDx({ name: 'x' }, [{ type: 'npm', name: 'a', version: '1', purl: 'pkg:npm/a@1', sources: [] }]).dependencies, undefined, 'no graph is guessed');
});

test('Cargo.toml and pyproject.toml manifests', () => {
  assert.deepEqual([...cargoNames(`[package]\nname = "me"\n[dependencies]\nserde = "1"\ntokio = { version = "1", features = ["full"] }\nrenamed = { package = "real-crate", version = "1" }\n[dev-dependencies.criterion]\nversion = "0.5"\n[target.'cfg(unix)'.dependencies]\nlibc = "0.2"\n[workspace.dependencies]\nanyhow.workspace = true\n`)].sort(), ['anyhow', 'criterion', 'libc', 'real-crate', 'serde', 'tokio']);
  assert.deepEqual([...pyprojectNames(`[project]\nname = "me"\ndependencies = [\n  "Django>=4",  # web\n  "requests[socks]>=2",\n]\n[project.optional-dependencies]\nyaml = ["PyYAML"]\n[dependency-groups]\ndev = ["pytest>=8"]\n[tool.poetry.dependencies]\npython = "^3.11"\nJinja2 = "^3"\n`)].sort(), ['django', 'jinja2', 'pytest', 'pyyaml', 'requests']);
});

test('Gemfile.lock DEPENDENCIES, go.mod replace and toolchain, requirements "# via"', () => {
  const g = byName(parseGemfileLock(`GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.8)\n    racc (1.7.1)\n\nDEPENDENCIES\n  rails (~> 7.0)\n`));
  assert.equal(g.rails.direct, true);
  assert.equal(g.racc.direct, false);
  const go = parseGoMod(`module x\n\ngo 1.22\n\ntoolchain go1.22.1\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v1.0.0\n\tgithub.com/e/f v2.0.0\n)\n\nreplace github.com/a/b v0.9.0 => github.com/z/b v0.9.1\nreplace github.com/c/d => ../d\nreplace github.com/e/f v2.0.0 => github.com/fork/f v2.0.1\n`);
  assert.deepEqual(go.map((c) => c.purl), ['pkg:golang/github.com/a/b@v1.0.0', 'pkg:golang/github.com/fork/f@v2.0.1', 'pkg:golang/stdlib@v1.22.1']);
  const r = byName(parseRequirements(`django==4.2.0 \\\n    --hash=sha256:${'a'.repeat(64)}\n    # via -r requirements.in\nsqlparse==0.4.4\n    # via django\n`));
  assert.equal(r.django.direct, true);
  assert.equal(r.django.hashes.length, 1, 'hashes on continuation lines are kept');
  assert.equal(r.sqlparse.direct, false);
  assert.equal(parseRequirements('flask==3.0.0\n')[0].direct, undefined, 'without annotations, unknown');
  const inline = byName(parseRequirements('click==8.1.7\n    # via flask\nflask==2.0.1  # via -r requirements.in\n'));
  assert.equal(inline.flask.direct, true);
  assert.equal(inline.click.direct, false);
  assert.equal(parseGoMod('module x\n\ngo 1.21.3\n').length, 0, 'the go line is a minimum, not the toolchain');
});

test('VEX: subcomponents, and statements about unmatched products hide nothing', () => {
  const st = readVex({ statements: [
    { vulnerability: { name: 'CVE-1' }, products: [{ '@id': 'https://example.com/app', subcomponents: [{ '@id': 'pkg:npm/lodash@4.17.20' }] }], status: 'not_affected' },
    { vulnerability: { name: 'CVE-2' }, products: [{ '@id': 'https://example.com/app' }], status: 'not_affected' },
  ] });
  const f = (id, purl) => ({ ids: [id], component: { purl } });
  assert.ok(vexFor(st, f('CVE-1', 'pkg:npm/lodash@4.17.20')));
  assert.equal(vexFor(st, f('CVE-1', 'pkg:npm/other@1.0.0')), null);
  assert.equal(vexFor(st, f('CVE-2', 'pkg:npm/lodash@4.17.20')), null);
  const none = readVex({ statements: [{ vulnerability: { name: 'CVE-4' }, products: [], status: 'not_affected' }, { vulnerability: { name: 'CVE-4' }, status: 'not_affected' }] });
  assert.equal(vexFor(none, f('CVE-4', 'pkg:npm/a@1')), null, 'a statement naming no product hides nothing');
  const cdx = readVex({ bomFormat: 'CycloneDX', vulnerabilities: [{ id: 'CVE-3', analysis: { state: 'not_affected' }, affects: [{ ref: 'not-a-component' }] }] });
  assert.equal(vexFor(cdx, f('CVE-3', 'pkg:npm/a@1')), null);
});

test('incident final report counts from the notification actually submitted', () => {
  const c = reportingClock({ kind: 'incident', awareAt: new Date('2026-11-06T09:30:00Z'), notifiedAt: new Date('2026-11-06T20:00:00Z') });
  assert.equal(c.steps[2].due.toISOString(), '2026-12-06T20:00:00.000Z');
});

test('SPDX checksums: SHA3 kept, entries without algorithm skipped', () => {
  const r = readSbom({ spdxVersion: 'SPDX-2.3', packages: [{ SPDXID: 'SPDXRef-a', checksums: [{ algorithm: 'SHA3-256', checksumValue: 'ab' }, { checksumValue: 'cd' }, { algorithm: 'SHA256', checksumValue: 'ef' }], externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/a@1' }] }] });
  assert.deepEqual(r.components[0].hashes, [{ alg: 'SHA3-256', content: 'ab' }, { alg: 'SHA-256', content: 'ef' }]);
});

test('CLI: unreadable lock file and incomplete data never exit 0', () => {
  const dir = mkdtempSync(join(tmpdir(), 'provetry-'));
  writeFileSync(join(dir, 'package-lock.json'), '{oops');
  const env = { ...process.env, PROVETRY_CACHE_DIR: mkdtempSync(join(tmpdir(), 'provetry-cache-')) };
  assert.equal(spawnSync(process.execPath, [cli, 'sbom', dir], { env }).status, 2);
  assert.equal(spawnSync(process.execPath, [cli, 'scan', dir, '--offline'], { env }).status, 2);
  const ok = spawnSync(process.execPath, [cli, 'scan', root, '--offline', '--fail-on', 'exploited'], { env, encoding: 'utf8' });
  assert.equal(ok.status, 2, 'an empty cache offline is incomplete, so the gate does not pass');
  const sbom = spawnSync(process.execPath, [cli, 'sbom', root, '--format', 'spdx'], { env, encoding: 'utf8' });
  assert.equal(sbom.status, 0);
  assert.equal(JSON.parse(sbom.stdout).spdxVersion, 'SPDX-2.3');
});
