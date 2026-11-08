// SPDX-License-Identifier: AGPL-3.0-only
// Checks an evidence journal exported from Provetry: every entry chained to the one before by SHA-256,
// so a changed, removed or reordered entry is found without trusting Provetry. The same computation as
// the service (shared/evidence.js there):
//   hash = SHA-256(previous hash + "\n" + canonical JSON of { seq, at, workspace, actor, action, subject, details })
// with keys sorted at every level, and 64 zeros before the first entry.
import { createHash } from 'node:crypto';

export const GENESIS = '0'.repeat(64);

/** JSON with keys sorted at every level, so the same entry always gives the same bytes. */
export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v ?? null);
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  return `{${Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
}

export function entryHash(prevHash, e) {
  const body = canonical({ seq: Number(e.seq), at: e.at, workspace: e.workspace, actor: e.actor, action: e.action, subject: e.subject, details: e.details ?? {} });
  return createHash('sha256').update(`${prevHash}\n${body}`).digest('hex');
}

/** Checks a chain (entries in order, details in clear): the first entry that does not hold, or null. */
export function verifyChain(entries) {
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (Number(e.seq) !== i + 1) return { seq: Number(e.seq), reason: 'missing or reordered entry' };
    if (e.prevHash !== prev) return { seq: Number(e.seq), reason: 'does not follow the previous entry' };
    if (entryHash(prev, e) !== e.hash) return { seq: Number(e.seq), reason: 'content changed' };
    prev = e.hash;
  }
  return null;
}

// RFC 3161 timestamps of the journal's head (the same check as the service: shared/tsa.js there).
/** Reads a DER length at `i`: [length, offset of the content]. */
function readLen(buf, i) {
  const b = buf[i];
  if (b < 0x80) return [b, i + 1];
  const k = b & 0x7f;
  if (k < 1 || k > 4 || i + 1 + k > buf.length) throw new Error('bad DER length');
  let n = 0;
  for (let j = 0; j < k; j++) n = n * 256 + buf[i + 1 + j];
  return [n, i + 1 + k];
}

/**
 * Checks a TimeStampResp: status granted (0) or granted with mods (1), and the digest asked for inside the
 * token. The authority's signature itself is for `openssl ts -verify` with its certificate.
 */
export function checkTimeStampResponse(resp, digestHex) {
  const buf = Buffer.from(resp);
  if (buf[0] !== 0x30) return { ok: false, reason: 'not a timestamp response' };
  const [, body] = readLen(buf, 1);
  if (buf[body] !== 0x30) return { ok: false, reason: 'no status' };
  const [, st] = readLen(buf, body + 1);
  if (buf[st] !== 0x02) return { ok: false, reason: 'no status' };
  const [sl, sv] = readLen(buf, st + 1);
  const status = buf.readUIntBE(sv, Math.min(sl, 6));
  if (status !== 0 && status !== 1) return { ok: false, reason: `refused (status ${status})` };
  if (!buf.includes(Buffer.from(digestHex, 'hex'))) return { ok: false, reason: 'the digest is not in the token' };
  return { ok: true };
}

/** Checks the timestamps of an export: each names an entry of the chain, and carries its hash. */
export function verifyTimestamps(entries, timestamps = []) {
  const bySeq = new Map(entries.map((e) => [Number(e.seq), e.hash]));
  for (const t of timestamps) {
    if (bySeq.get(Number(t.seq)) !== t.hash) return { seq: Number(t.seq), reason: 'the timestamped entry is not in this journal' };
    const c = checkTimeStampResponse(Buffer.from(String(t.response), 'base64'), t.hash);
    if (!c.ok) return { seq: Number(t.seq), reason: `timestamp: ${c.reason}` };
  }
  return null;
}
