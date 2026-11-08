import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { reach, fromGovulncheck, mergeReach, canonicalPurl } from '../src/reach.js';
import { readVex, vexFor } from '../src/vex.js';

const root = new URL('./fixtures/reach', import.meta.url).pathname;
const fixture = (n) => readFileSync(join(root, n), 'utf8');
const now = new Date('2026-11-08T10:00:00Z');

/** Plays govulncheck: the recorded output of each module. */
function fakeExec(answers) {
  return async (cmd, args, { cwd }) => {
    if (args[0] === '-version') return { code: 0, stdout: 'Go: go1.22.1\nScanner: govulncheck@v1.1.4\n', stderr: '' };
    const mod = cwd.split('/').pop();
    return answers[mod] ?? { code: 1, stdout: '', stderr: 'go: cannot find main module' };
  };
}

test('govulncheck purls become the SBOM purls', () => {
  assert.equal(canonicalPurl('pkg:golang/golang.org%2Fx%2Fnet@v0.15.0'), 'pkg:golang/golang.org/x/net@v0.15.0');
  assert.equal(canonicalPurl('pkg:golang/stdlib@v1.22.1'), 'pkg:golang/stdlib@v1.22.1');
});

test('one module: not called is not affected, called is affected, with the reason', () => {
  const st = fromGovulncheck(JSON.parse(fixture('svc.openvex.json')), { module: 'svc', version: 'v1.1.4' });
  assert.equal(st.length, 2);
  assert.equal(st[0].purl, 'pkg:golang/golang.org/x/net@v0.15.0');
  assert.equal(st[0].status, 'not_affected');
  assert.match(st[0].status_notes, /govulncheck v1\.1\.4 found no call to the vulnerable code from the module in svc/);
  assert.equal(st[1].status, 'affected');
});

test('several modules: a vulnerability called in any of them makes the product affected', async () => {
  const r = await reach(root, {
    product: 'pkg:generic/demo@1.0.0', now,
    exec: fakeExec({ svc: { code: 0, stdout: fixture('svc.openvex.json'), stderr: '' }, tools: { code: 0, stdout: fixture('tools.openvex.json'), stderr: '' } }),
  });
  assert.deepEqual(r.modules.sort(), ['svc', 'tools']);
  assert.deepEqual(r.errors, []);
  const net = r.doc.statements.find((s) => s.vulnerability.name === 'GO-2023-2102');
  assert.equal(net.status, 'affected', 'tools calls it, so the product is affected');
  assert.equal(net.products[0]['@id'], 'pkg:generic/demo@1.0.0');
  assert.equal(r.doc.statements.find((s) => s.vulnerability.name === 'GO-2022-1059').status, 'affected');
});

test('the document is valid OpenVEX that `scan --vex` applies to the right component only', async () => {
  const r = await reach(root, { now, exec: fakeExec({ svc: { code: 0, stdout: fixture('svc.openvex.json'), stderr: '' }, tools: { code: 0, stdout: '{"statements":[]}', stderr: '' } }) });
  const statements = readVex(JSON.parse(JSON.stringify(r.doc)));
  const finding = (ids, purl) => ({ ids, component: { purl } });
  // Matched through the CVE alias, as `scan` reports it.
  assert.equal(vexFor(statements, finding(['CVE-2023-39325', 'GO-2023-2102'], 'pkg:golang/golang.org/x/net@v0.15.0'))?.status, 'not_affected');
  assert.equal(vexFor(statements, finding(['CVE-2023-39325'], 'pkg:golang/golang.org/x/net@v0.17.0')), null, 'another version is not covered');
  assert.match(r.doc.statements.find((s) => s.vulnerability.name === 'GO-2023-2102').impact_statement, /no call/);
});

test('a module where govulncheck fails is reported; what it depends on is not declared "not affected"', async () => {
  const r = await reach(root, { now, exec: fakeExec({ svc: { code: 0, stdout: fixture('svc.openvex.json'), stderr: '' } }) });
  assert.deepEqual(r.errors, [{ module: 'tools', error: 'go: cannot find main module' }]);
  const net = r.doc.statements.find((s) => s.vulnerability.name === 'GO-2023-2102');
  assert.equal(net.status, 'under_investigation', 'tools requires golang.org/x/net and was not checked');
  assert.match(net.status_notes, /could not be checked/);
  assert.equal(net.justification, undefined);
});

test('the standard library and testdata modules are left out', () => {
  const doc = { statements: [{ vulnerability: { name: 'GO-1' }, products: [{ subcomponents: [{ '@id': 'pkg:golang/stdlib@v1.25.0' }] }], status: 'not_affected', justification: 'vulnerable_code_not_present' }] };
  assert.deepEqual(fromGovulncheck(doc), []);
});

test('without govulncheck: a clear message', async () => {
  const exec = async () => { throw Object.assign(new Error('x'), { code: 'ENOENT' }); };
  await assert.rejects(reach(root, { exec }), /go install golang\.org\/x\/vuln\/cmd\/govulncheck@latest/);
});

test('merge: imported but never called describes the product better than not imported', () => {
  const a = { vulnerability: { name: 'GO-1' }, purl: 'pkg:golang/x/y@v1', status: 'not_affected', justification: 'vulnerable_code_not_present', status_notes: 'a' };
  const b = { ...a, justification: 'vulnerable_code_not_in_execute_path', status_notes: 'b' };
  assert.equal(mergeReach([[a], [b]], { now }).statements[0].justification, 'vulnerable_code_not_in_execute_path');
  assert.equal(mergeReach([[b], [a]], { now }).statements[0].justification, 'vulnerable_code_not_in_execute_path');
});
