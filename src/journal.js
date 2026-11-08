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
