import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { canonical, entryHash, verifyChain, verifyTimestamps, GENESIS } from '../src/journal.js';

function chain(n) {
  const out = [];
  let prev = GENESIS;
  for (let i = 1; i <= n; i++) {
    const e = { seq: i, at: `2026-11-08T10:0${i}:00.000Z`, workspace: 'w', actor: 'u', action: 'vex.saved', subject: 'p', details: { vuln: `CVE-2026-${i}`, nested: { b: 1, a: [2, { z: 1, y: 2 }] } } };
    const hash = entryHash(prev, e);
    out.push({ ...e, prevHash: prev, hash });
    prev = hash;
  }
  return out;
}

test('canonical JSON sorts keys at every level', () => {
  assert.equal(canonical({ b: 1, a: { d: [1, { c: 2, b: 1 }], c: null } }), '{"a":{"c":null,"d":[1,{"b":1,"c":2}]},"b":1}');
});

test('a chain holds; any change, removal or reordering is found', () => {
  const c = chain(4);
  assert.equal(verifyChain(c), null);
  assert.deepEqual(verifyChain(c.map((e, i) => (i === 1 ? { ...e, details: { ...e.details, vuln: 'CVE-X' } } : e))), { seq: 2, reason: 'content changed' });
  assert.equal(verifyChain([c[0], c[2], c[3]]).seq, 3);
  assert.equal(verifyChain([c[1], c[0], c[2], c[3]]).seq, 2);
  const forged = c.map((e) => ({ ...e }));
  forged[3].action = 'case.close';
  assert.equal(verifyChain(forged).reason, 'content changed');
});

test('CLI: verify-journal says OK or where it breaks', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pj-'));
  const ok = join(dir, 'ok.json');
  const c = chain(3);
  writeFileSync(ok, JSON.stringify({ format: 'provetry-evidence-journal', entries: c, head: c[2].hash }));
  const cli = new URL('../src/cli.js', import.meta.url).pathname;
  assert.match(execFileSync(process.execPath, [cli, 'verify-journal', ok], { encoding: 'utf8' }), /^OK: 3 entries, chain intact\./);
  assert.match(execFileSync(process.execPath, [cli, 'verify-journal', ok, '--head', c[1].hash], { encoding: 'utf8' }), /1 kept hash found/);
  let cut = 0;
  try { execFileSync(process.execPath, [cli, 'verify-journal', ok, '--head', 'f'.repeat(64)], { encoding: 'utf8' }); } catch (e) { cut = e.status; }
  assert.equal(cut, 1, 'a kept hash missing from the journal: rewritten history');
  const bad = join(dir, 'bad.json');
  c[1].at = '2026-11-08T09:00:00.000Z';
  writeFileSync(bad, JSON.stringify({ format: 'provetry-evidence-journal', entries: c }));
  let code = 0, out = '';
  try { execFileSync(process.execPath, [cli, 'verify-journal', bad], { encoding: 'utf8' }); } catch (e) { code = e.status; out = e.stdout; }
  assert.equal(code, 1);
  assert.match(out, /BROKEN at entry 2: content changed/);
});

test('timestamps: they must name an entry of the chain and carry its hash', () => {
  const c = chain(2);
  const der = (hex) => Buffer.concat([Buffer.from([0x30, 0x27, 0x30, 0x03, 0x02, 0x01, 0x00, 0x04, 0x20]), Buffer.from(hex, 'hex')]).toString('base64');
  assert.equal(verifyTimestamps(c, [{ seq: 2, hash: c[1].hash, response: der(c[1].hash) }]), null);
  assert.match(verifyTimestamps(c, [{ seq: 2, hash: c[0].hash, response: der(c[0].hash) }]).reason, /not in this journal/);
  assert.match(verifyTimestamps(c, [{ seq: 1, hash: c[0].hash, response: der(c[1].hash) }]).reason, /digest is not in the token/);
  const refused = Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]).toString('base64');
  assert.match(verifyTimestamps(c, [{ seq: 1, hash: c[0].hash, response: refused }]).reason, /refused/);
});
