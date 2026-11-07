// SPDX-License-Identifier: AGPL-3.0-only
// CISA Known Exploited Vulnerabilities: vulnerabilities confirmed to be exploited in the wild.
// https://www.cisa.gov/known-exploited-vulnerabilities-catalog
import { cacheGet, cacheSet, getJson } from '../util.js';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const MAX_AGE = 24 * 3600;

/** Map<cve, { dateAdded, ransomware }> */
export async function loadKev(ctx) {
  const cached = cacheGet(ctx, 'kev', MAX_AGE);
  if (cached) return new Map(Object.entries(cached));
  const { status, json } = await getJson(ctx, KEV_URL);
  if (status !== 200 || !Array.isArray(json?.vulnerabilities)) throw new Error(`HTTP ${status}`);
  const obj = {};
  for (const v of json.vulnerabilities) {
    if (v.cveID) obj[v.cveID] = { dateAdded: v.dateAdded ?? null, ransomware: /^known$/i.test(String(v.knownRansomwareCampaignUse ?? '').trim()) };
  }
  cacheSet(ctx, 'kev', obj);
  return new Map(Object.entries(obj));
}
