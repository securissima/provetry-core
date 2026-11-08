// SPDX-License-Identifier: AGPL-3.0-only
// FIRST EPSS (Exploit Prediction Scoring System): the probability, from 0 to 1, that a vulnerability is
// exploited in the next 30 days, recomputed daily, with its percentile among all scored CVEs.
// https://www.first.org/epss/ . It only scores CVEs, and says nothing about a vulnerability already
// exploited (that is what CISA KEV and ENISA EUVD are for): it sorts what is not exploited yet.
import { cacheGet, cacheSet, getJson, mapLimit, CVE_RE } from '../util.js';

export const EPSS_URL = 'https://api.first.org/data/v1/epss';
const MAX_AGE = 24 * 3600;
const BATCH = 100;

/** A score of 10% or more: among the small share of vulnerabilities attackers actually go after. */
export const EPSS_LIKELY = 0.1;

/** Map<cve, { score, percentile, date }> for the CVEs that have a score. Throws when the service cannot be reached at all. */
export async function loadEpss(ctx, cveList) {
  const out = new Map();
  const missing = [];
  for (const cve of new Set(cveList.filter((c) => CVE_RE.test(c)))) {
    const c = cacheGet(ctx, `epss:${cve}`, MAX_AGE);
    if (c === undefined) missing.push(cve);
    else if (c) out.set(cve, c);
  }
  const batches = [];
  for (let i = 0; i < missing.length; i += BATCH) batches.push(missing.slice(i, i + BATCH));
  let failed = 0;
  await mapLimit(batches, 2, async (batch) => {
    try {
      const { status, json } = await getJson(ctx, `${EPSS_URL}?cve=${batch.join(',')}`);
      if (status !== 200 || !Array.isArray(json?.data)) { failed++; return; }
      const seen = new Set();
      for (const row of json.data) {
        const score = Number(row.epss);
        const percentile = Number(row.percentile);
        if (!CVE_RE.test(row.cve ?? '') || !Number.isFinite(score) || !Number.isFinite(percentile)) continue;
        const v = { score, percentile, date: typeof row.date === 'string' ? row.date : null };
        out.set(row.cve, v);
        cacheSet(ctx, `epss:${row.cve}`, v);
        seen.add(row.cve);
      }
      // Not scored (too recent, or rejected): remembered as such for a day.
      for (const cve of batch) if (!seen.has(cve)) cacheSet(ctx, `epss:${cve}`, null);
    } catch (e) {
      if (e.code === 'OFFLINE') throw e;
      failed++;
    }
  });
  if (batches.length && failed === batches.length) throw new Error('EPSS unavailable');
  return out;
}

/** The score of a finding: the highest among its CVE identifiers (one advisory can carry several). */
export function epssOf(epss, ids) {
  let best = null;
  for (const id of ids) {
    const e = epss.get(id);
    if (e && (!best || e.score > best.score)) best = { cve: id, ...e };
  }
  return best;
}
