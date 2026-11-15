// SPDX-License-Identifier: AGPL-3.0-only
// ENISA's European Vulnerability Database (EUVD), the database the CRA itself refers to (Article 14 and
// NIS2 Article 12): its list of vulnerabilities known to be exploited. https://euvd.enisa.europa.eu
// The service has no published stability guarantee, so this source is best effort: when it does not answer
// as expected, the scan carries on with the others and says so.
import { cacheGet, cacheSet, getJson, CVE_RE } from '../util.js';

export const EUVD_API = 'https://euvdservices.enisa.europa.eu/api';
const MAX_AGE = 24 * 3600;
const PAGE = 100; // the largest page the search accepts
const MAX_PAGES = 60;

/**
 * The full list comes from the search, filtered on exploited entries: `{ items, total }`, paginated from page 0.
 * (`/exploitedvulnerabilities` only gives the latest few entries and ignores `size`; `/vulnerabilities` does not
 * exist and answers 404.)
 */
export const euvdExploitedPage = (page) => `${EUVD_API}/search?exploited=true&size=${PAGE}&page=${page}`;

/** Map<id, { euvd, exploitedSince }> keyed by every alias (CVE, GHSA…) of each exploited entry. */
export async function loadEuvdExploited(ctx) {
  const cached = cacheGet(ctx, 'euvd-exploited', MAX_AGE);
  if (cached) return new Map(Object.entries(cached));
  const obj = {};
  let total = Infinity;
  for (let page = 0; page < MAX_PAGES && page * PAGE < total; page++) {
    const { status, json } = await getJson(ctx, euvdExploitedPage(page));
    if (status !== 200 || !Array.isArray(json?.items)) throw new Error(`HTTP ${status}`);
    total = Number(json.total ?? 0);
    for (const it of json.items) {
      const aliases = String(it.aliases ?? '').split(/\s+/).filter(Boolean);
      const entry = { euvd: it.id ?? null, exploitedSince: it.exploitedSince ?? null };
      for (const a of aliases) if (CVE_RE.test(a) || /^GHSA-/.test(a)) obj[a] = entry;
    }
    if (json.items.length < PAGE) break;
  }
  if (!Object.keys(obj).length) throw new Error('empty answer');
  cacheSet(ctx, 'euvd-exploited', obj);
  return new Map(Object.entries(obj));
}
