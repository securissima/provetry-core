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

// RFC 3161 timestamps of the journal's head: parsed and checked by ./tsa.js (hash, CMS signature, and,
// when the authority's CA certificates are given, who signed).
export { checkTimeStampResponse, readCertificates } from './tsa.js';
import { checkTimeStampResponse } from './tsa.js';

/**
 * Checks the timestamps of an export: each names an entry of the chain and is a valid token for its hash.
 * { broken: { seq, reason } } or { checked: [{ seq, genTime, signer, trusted }] } (trusted: null without `trust`).
 */
export function verifyTimestamps(entries, timestamps = [], { trust } = {}) {
  const bySeq = new Map(entries.map((e) => [Number(e.seq), e.hash]));
  const checked = [];
  for (const t of timestamps) {
    if (bySeq.get(Number(t.seq)) !== t.hash) return { broken: { seq: Number(t.seq), reason: 'the timestamped entry is not in this journal' } };
    const c = checkTimeStampResponse(Buffer.from(String(t.response), 'base64'), t.hash, { trust });
    if (!c.ok) return { broken: { seq: Number(t.seq), reason: `timestamp: ${c.reason}` } };
    checked.push({ seq: Number(t.seq), genTime: c.genTime, signer: c.signer, trusted: c.trusted });
  }
  return { checked };
}

/**
 * Entries first covered by a timestamp long after the time they give (stamps are daily): they may have
 * been written, or rewritten, later than they say. [{ from, to, stampedAt }] by ranges of entries.
 */
export function lateCoverage(entries, checked, { days = 2 } = {}) {
  const out = [];
  let covered = 0;
  for (const t of [...checked].sort((a, b) => a.genTime.localeCompare(b.genTime))) {
    if (t.seq <= covered) continue;
    const late = entries.filter((e) => Number(e.seq) > covered && Number(e.seq) <= t.seq && Date.parse(t.genTime) - Date.parse(e.at) > days * 86400e3).map((e) => Number(e.seq));
    if (late.length) out.push({ from: late[0], to: late.at(-1), stampedAt: t.genTime });
    covered = t.seq;
  }
  return out;
}
