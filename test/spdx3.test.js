import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { collect } from '../src/lockfiles/index.js';
import { toSpdx3 } from '../src/sbom/write.js';
import { readSbom } from '../src/sbom/read.js';

const root = new URL('./fixtures/proj', import.meta.url).pathname;
const fixed = { now: new Date('2026-11-07T10:00:00Z'), serial: '00000000-0000-4000-8000-000000000000' };
const key = (c) => `${c.purl}|${c.scope}`;
const schema = JSON.parse(readFileSync(new URL('./fixtures/spdx3/spdx-schema-3-0-1.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ strict: false, allErrors: true });
addFormats(ajv);
const validate = ajv.compile(schema);
const valid = (doc) => { const ok = validate(doc); return ok ? true : JSON.stringify(validate.errors.slice(0, 5)); };

test('SPDX 3.0.1: valid against the official schema, with and without supplier, complete or not', async () => {
  const { components } = await collect(root);
  assert.ok(components.length > 10);
  for (const product of [{ name: 'demo', version: '1.2.0', supplier: 'Acme' }, { name: 'demo' }]) {
    for (const extra of [{}, { incomplete: ['pom.xml: parent outside the repository'], unresolved: 2 }]) {
      const doc = toSpdx3(product, components, { ...fixed, ...extra });
      assert.equal(valid(doc), true);
    }
  }
  // The check is real: a wrong value is refused.
  const bad = toSpdx3({ name: 'demo' }, components, fixed);
  bad['@graph'].find((e) => e.type === 'software_Sbom').software_sbomType = ['compiled'];
  assert.notEqual(valid(bad), true);
});

test('SPDX 3.0.1: ids unique and resolvable, collections list every element, relationships point inside', async () => {
  const { components } = await collect(root);
  const doc = toSpdx3({ name: 'demo', version: '1.2.0', supplier: 'Acme' }, components, fixed);
  assert.equal(doc['@context'], 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld');
  const graph = doc['@graph'];
  const ids = graph.filter((e) => e.spdxId).map((e) => e.spdxId);
  assert.equal(new Set(ids).size, ids.length, 'spdxIds are unique');
  const known = new Set(ids);
  const info = graph.find((e) => e.type === 'CreationInfo');
  assert.equal(info.specVersion, '3.0.1');
  assert.equal(info.created, '2026-11-07T10:00:00Z');
  for (const a of [...info.createdBy, ...info.createdUsing]) assert.ok(known.has(a));
  const spdxDoc = graph.find((e) => e.type === 'SpdxDocument');
  const sbom = graph.find((e) => e.type === 'software_Sbom');
  for (const e of [...spdxDoc.element, ...spdxDoc.rootElement, ...sbom.element, ...sbom.rootElement]) assert.ok(known.has(e), e);
  for (const e of graph) if (e.creationInfo) assert.equal(e.creationInfo, '_:creationinfo');
  for (const r of graph.filter((e) => /Relationship$/.test(e.type))) for (const t of [r.from, ...r.to]) assert.ok(known.has(t));
  const pkgs = graph.filter((e) => e.type === 'software_Package' && e.software_packageUrl);
  assert.equal(pkgs.length, components.length);
  for (const p of pkgs) for (const h of p.verifiedUsing ?? []) assert.match(h.hashValue, /^[0-9a-f]+$/);
  const top = graph.find((e) => e.spdxId === sbom.rootElement[0]);
  assert.equal(top.software_primaryPurpose, 'application');
  assert.equal(graph.find((e) => e.spdxId === top.suppliedBy).name, 'Acme');
});

test('SPDX 3.0.1: reading it back gives the same components, dev scope and notices included', async () => {
  const { components } = await collect(root);
  const doc = toSpdx3({ name: 'demo', version: '1.2.0' }, components, { ...fixed, incomplete: ['two notes'], unresolved: 3 });
  const back = readSbom(JSON.parse(JSON.stringify(doc)));
  assert.equal(back.format, 'SPDX');
  assert.equal(back.specVersion, 'SPDX-3.0.1');
  assert.equal(back.name, 'demo-1.2.0');
  assert.deepEqual(back.components.map(key).sort(), components.filter((c) => c.scope !== 'optional').map(key).concat(components.filter((c) => c.scope === 'optional').map((c) => `${c.purl}|required`)).sort());
  assert.deepEqual(back.notices, [{ text: 'two notes', missing: 3 }]);
});

test('SPDX 3.0.1: the official example validates, and is read', () => {
  const ex = JSON.parse(readFileSync(new URL('./fixtures/spdx3/package_sbom.json', import.meta.url), 'utf8'));
  assert.equal(valid(ex), true);
  const back = readSbom(ex);
  assert.equal(back.format, 'SPDX');
  assert.equal(back.specVersion, 'SPDX-3.0.1');
  assert.equal(back.components.length, 0, 'the example holds a file, not packages with a package URL');
});

test('SPDX 3.0.1: completeness is never claimed, only "incomplete" when something is missing; no supplier means a software author', async () => {
  const { components } = await collect(root);
  const rel = (d) => d['@graph'].find((e) => e.type === 'Relationship');
  assert.equal(rel(toSpdx3({ name: 'demo' }, components, fixed)).completeness, undefined);
  assert.equal(rel(toSpdx3({ name: 'demo' }, components, { ...fixed, incomplete: ['x'] })).completeness, 'incomplete');
  const g = toSpdx3({ name: 'demo' }, components, fixed)['@graph'];
  const author = g.find((e) => e.spdxId === g[0].createdBy[0]);
  assert.equal(author.type, 'SoftwareAgent');
});

test('SPDX 3 reader: other shapes (full IRIs, single values instead of arrays, inline creation info, incomplete) and junk', () => {
  const T = 'https://spdx.org/rdf/3.0.1/terms/';
  const doc = { '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld', '@graph': [
    { type: 'SpdxDocument', spdxId: 'urn:d', name: 'x', creationInfo: { type: 'CreationInfo', specVersion: '3.0.1', created: '2026-01-01T00:00:00Z', createdBy: ['urn:a'] } },
    { type: 'software_Package', spdxId: 'urn:p1', name: 'a', externalIdentifier: { type: 'ExternalIdentifier', externalIdentifierType: 'packageUrl', identifier: 'pkg:npm/a@1.0.0' }, verifiedUsing: { type: 'Hash', algorithm: `${T}Core/HashAlgorithm/sha256`, hashValue: 'ab' } },
    { type: 'software_Package', spdxId: 'urn:p2', name: 'b', software_packageUrl: 'pkg:npm/b@2.0.0', verifiedUsing: {} },
    { type: 'software_Package', spdxId: 'urn:p3', name: 'c', software_packageUrl: 42, externalIdentifier: {} },
    { type: 'LifecycleScopedRelationship', spdxId: 'urn:r', from: 'urn:x', relationshipType: `${T}Core/RelationshipType/dependsOn`, scope: `${T}Core/LifecycleScopeType/test`, to: 'urn:p2', completeness: 'incomplete' },
    null, 'junk',
  ] };
  const back = readSbom(doc);
  assert.equal(back.specVersion, 'SPDX-3.0.1');
  assert.deepEqual(back.components.map((c) => [c.purl, c.scope, c.hashes.length]), [['pkg:npm/a@1.0.0', 'required', 1], ['pkg:npm/b@2.0.0', 'dev', 0]]);
  assert.equal(back.notices.length, 1);
});
