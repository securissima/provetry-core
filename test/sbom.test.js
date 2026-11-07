import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collect } from '../src/lockfiles/index.js';
import { toCycloneDx, toSpdx } from '../src/sbom/write.js';
import { readSbom } from '../src/sbom/read.js';

const root = new URL('./fixtures/proj', import.meta.url).pathname;
const fixed = { now: new Date('2026-11-07T10:00:00Z'), serial: 'urn:uuid:00000000-0000-4000-8000-000000000000' };
const key = (c) => `${c.purl}|${c.scope}`;

test('CycloneDX: valid shape, and reading it back gives the same components', async () => {
  const { components } = await collect(root);
  assert.ok(components.length > 10);
  const bom = toCycloneDx({ name: 'demo', version: '1.2.0', supplier: 'Acme' }, components, fixed);
  assert.equal(bom.specVersion, '1.6');
  assert.equal(bom.serialNumber, fixed.serial);
  assert.equal(bom.metadata.timestamp, '2026-11-07T10:00:00.000Z');
  assert.equal(bom.metadata.component.supplier.name, 'Acme');
  const refs = new Set(bom.components.map((c) => c['bom-ref']));
  assert.equal(refs.size, bom.components.length, 'bom-refs are unique');
  for (const d of bom.dependencies[0].dependsOn) assert.ok(refs.has(d));
  for (const c of bom.components) for (const h of c.hashes ?? []) assert.match(h.content, /^[0-9a-f]+$/i);
  const back = readSbom(JSON.parse(JSON.stringify(bom)));
  assert.equal(back.format, 'CycloneDX');
  assert.equal(back.name, 'demo');
  assert.deepEqual(back.components.map(key).sort(), components.map(key).sort());
});

test('SPDX: unique ids, relationships, and reading it back keeps dev scope', async () => {
  const { components } = await collect(root);
  const doc = toSpdx({ name: 'demo', version: '1.2.0' }, components, fixed);
  assert.equal(doc.spdxVersion, 'SPDX-2.3');
  assert.match(doc.creationInfo.created, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  const ids = doc.packages.map((p) => p.SPDXID);
  assert.equal(new Set(ids).size, ids.length);
  for (const id of ids) assert.match(id, /^SPDXRef-[A-Za-z0-9.-]+$/);
  for (const r of doc.relationships) {
    assert.ok(ids.includes(r.spdxElementId) || r.spdxElementId === 'SPDXRef-DOCUMENT');
    assert.ok(ids.includes(r.relatedSpdxElement));
  }
  const back = readSbom(JSON.parse(JSON.stringify(doc)));
  assert.deepEqual(back.components.map((c) => `${c.purl}|${c.scope === 'dev' ? 'dev' : 'x'}`).sort(), components.map((c) => `${c.purl}|${c.scope === 'dev' ? 'dev' : 'x'}`).sort());
});

test('SPDX ids stay unique when names collapse to the same characters', () => {
  const comps = [
    { type: 'npm', name: 'a_b', version: '1.0.0', purl: 'pkg:npm/a_b@1.0.0', scope: 'required', direct: true, hashes: [], sources: [] },
    { type: 'npm', name: 'a+b', version: '1.0.0', purl: 'pkg:npm/a%2Bb@1.0.0', scope: 'required', direct: true, hashes: [], sources: [] },
  ];
  const ids = toSpdx({ name: 'x' }, comps, fixed).packages.map((p) => p.SPDXID);
  assert.equal(new Set(ids).size, 3);
});

test('readSbom refuses other documents and skips components without a versioned purl', () => {
  assert.throws(() => readSbom({ hello: 1 }));
  const r = readSbom({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'x' }, { purl: 'pkg:npm/y' }, { purl: 'pkg:npm/z@1.0.0', components: [{ purl: 'pkg:pypi/requests@2.31.0' }] }] });
  assert.deepEqual(r.components.map((c) => c.purl), ['pkg:npm/z@1.0.0', 'pkg:pypi/requests@2.31.0']);
});
