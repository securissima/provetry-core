// SPDX-License-Identifier: AGPL-3.0-only
// Known vulnerabilities per component, from OSV.dev (https://osv.dev): one database that aggregates the
// GitHub advisories, the Python, Go and Rust advisory databases, RubySec, and more. Queried by package URL;
// operating-system packages (Debian, Ubuntu, Alpine, Wolfi, Chainguard, and the RPM distributions OSV carries:
// Red Hat, AlmaLinux, Rocky Linux, openSUSE Leap, Mageia) by ecosystem and release, name and version.
import { cvss3Score, ratingOf } from './cvss.js';
import { mapLimit, cacheGet, cacheSet, getJson, CVE_RE } from '../util.js';
import { parsePurl, fullName, OSV_ECOSYSTEM, osvOsPackage } from '../purl.js';

export const OSV_API = 'https://api.osv.dev/v1';
const BATCH = 1000;
const QUERY_MAX_AGE = 6 * 3600;
const DETAIL_MAX_AGE = 30 * 24 * 3600;

/**
 * For each purl, the list of { id, modified } OSV reports as affecting it.
 * Returns Map<purl, Array<{id, modified}>>; purls that could not be queried are left out.
 */
export async function queryPurls(ctx, purls) {
  const out = new Map();
  const missing = [];
  for (const p of new Set(purls)) {
    const c = cacheGet(ctx, `osvq:${p}`, QUERY_MAX_AGE);
    if (c) out.set(p, c);
    else missing.push(p);
  }
  // One purl may need several queries (an RPM package: every name in every repository's ecosystem).
  const asks = missing.flatMap((p) => osvQueries(p).map((query) => ({ p, query })));
  const found = new Map(missing.map((p) => [p, new Map()]));
  for (let i = 0; i < asks.length; i += BATCH) {
    const batch = asks.slice(i, i + BATCH);
    const { status, json } = await getJson(ctx, `${OSV_API}/querybatch`, { method: 'POST', body: { queries: batch.map((a) => a.query) } });
    if (status !== 200 || !Array.isArray(json?.results)) throw new Error(`OSV HTTP ${status}`);
    for (let j = 0; j < batch.length; j++) {
      const r = json.results[j] ?? {};
      let vulns = (r.vulns ?? []).map((v) => ({ id: v.id, modified: v.modified ?? '' }));
      // A package with very many advisories is paged: fetch the rest one query at a time.
      let token = r.next_page_token;
      for (let n = 0; token; n++) {
        if (n >= 50) throw new Error(`OSV: too many result pages for ${batch[j].p}`);
        const more = await getJson(ctx, `${OSV_API}/query`, { method: 'POST', body: { ...batch[j].query, page_token: token } });
        if (more.status !== 200) throw new Error(`OSV HTTP ${more.status}`);
        vulns = vulns.concat((more.json?.vulns ?? []).map((v) => ({ id: v.id, modified: v.modified ?? '' })));
        token = more.json?.next_page_token;
      }
      for (const v of vulns) found.get(batch[j].p).set(v.id, v);
    }
  }
  // Kept only once every query of the purl has answered: a failed batch above throws before this.
  for (const [p, m] of found) {
    const vulns = [...m.values()];
    out.set(p, vulns);
    cacheSet(ctx, `osvq:${p}`, vulns);
  }
  return out;
}

/** The OSV queries for a purl: by purl, or for an operating-system package by ecosystem, name and version (each spelling). */
export function osvQueries(purl) {
  const os = osvOsPackage(purl);
  if (!os) return [{ package: { purl } }];
  return os.ecosystems.flatMap((ecosystem) => os.names.map((name) => ({ package: { name, ecosystem }, version: os.version })));
}
/** The first of them (the only one outside RPM). */
export const osvQuery = (purl) => osvQueries(purl)[0];

/** The ecosystem and name advisories use for a component (OSV spelling). */
function advisoryKey(purl) {
  const p = parsePurl(purl);
  if (!p) return null;
  const os = osvOsPackage(purl);
  // Operating-system packages: the exact release ("Debian:12"), as one record covers several releases.
  return os ? { p, ecos: os.ecosystems, names: os.names, exact: true, name: os.name } : { p, eco: OSV_ECOSYSTEM[p.type], exact: false, name: fullName(p) };
}
const ecoMatches = (k, ecosystem) => (k.exact ? k.ecos.includes(ecosystem) : ecosystem?.split(':')[0] === k.eco);
const nameMatches = (k, name) => (k.exact ? k.names.includes(name) : name === k.name);

/** Full OSV records for the given { id, modified } pairs. Returns Map<id, record>. Records that fail are left out. */
export async function loadDetails(ctx, refs) {
  const uniq = [...new Map(refs.map((r) => [r.id, r])).values()];
  const out = new Map();
  await mapLimit(uniq, 8, async ({ id, modified }) => {
    const key = `osv:${id}:${modified}`;
    let rec = cacheGet(ctx, key, DETAIL_MAX_AGE);
    if (!rec) {
      try {
        const { status, json } = await getJson(ctx, `${OSV_API}/vulns/${encodeURIComponent(id)}`);
        if (status !== 200 || !json?.id) return;
        rec = json;
        cacheSet(ctx, key, rec);
      } catch {
        return;
      }
    }
    out.set(id, rec);
  });
  return out;
}

const DB_SEVERITY = { CRITICAL: 'critical', HIGH: 'high', IMPORTANT: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
// AlmaLinux and Rocky Linux advisories carry the vendor's rating only as the first word of their summary
// ("Important: openssl security update").
const SUMMARY_RATING = /^(Critical|Important|Moderate|Low): /;

/** Severity of an OSV record: the highest CVSS 3.x score it carries, else the severity its database states. */
export function severityOf(rec) {
  const vectors = [...(rec.severity ?? []), ...(rec.affected ?? []).flatMap((a) => a.severity ?? [])];
  let score = null;
  let vector = null;
  for (const s of vectors) {
    if (s.type !== 'CVSS_V3') continue;
    const v = cvss3Score(s.score);
    if (v !== null && (score === null || v > score)) {
      score = v;
      vector = s.score;
    }
  }
  if (score !== null) return { rating: ratingOf(score), score, vector };
  const worded = /^(ALSA|RLSA|RXSA|ALBA|RLBA|ALEA|RLEA)-/.test(String(rec.id ?? '')) ? SUMMARY_RATING.exec(String(rec.summary ?? ''))?.[1] : null;
  const stated = [rec.database_specific?.severity, worded, ...(rec.affected ?? []).map((a) => a.ecosystem_specific?.severity ?? a.database_specific?.severity)]
    .map((s) => DB_SEVERITY[String(s ?? '').toUpperCase()])
    .filter(Boolean);
  const order = ['critical', 'high', 'medium', 'low'];
  const best = order.find((r) => stated.includes(r));
  const v4 = vectors.find((s) => s.type === 'CVSS_V4');
  return { rating: best ?? 'unknown', score: null, vector: v4?.score ?? null };
}

/** Versions that fix the record for this component, read from its affected ranges. */
export function fixedVersions(rec, purl) {
  const k = advisoryKey(purl);
  if (!k) return [];
  const { p, name } = k;
  const norm = (s) => (p.type === 'pypi' ? s.toLowerCase().replace(/[-_.]+/g, '-') : s);
  const fixed = new Set();
  for (const a of rec.affected ?? []) {
    const ap = a.package ?? {};
    const matches = k.exact ? ecoMatches(k, ap.ecosystem) && nameMatches(k, ap.name) : (ap.purl && parsePurl(ap.purl) && norm(fullName(parsePurl(ap.purl))) === norm(name)) || (ecoMatches(k, ap.ecosystem) && norm(ap.name ?? '') === norm(name));
    if (!matches) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
  }
  return [...fixed];
}

/**
 * The functions a record names as affected for a component, when its database gives them: RustSec
 * (`ecosystem_specific.affects.functions`, full paths such as "smallvec::SmallVec::insert_many").
 */
export function affectedFunctions(rec, purl) {
  const k = advisoryKey(purl);
  if (!k) return [];
  const { name } = k;
  const out = new Set();
  for (const a of rec.affected ?? []) {
    const ap = a.package ?? {};
    if (!((ecoMatches(k, ap.ecosystem) && nameMatches(k, ap.name)) || (!k.exact && ap.purl && parsePurl(ap.purl) && fullName(parsePurl(ap.purl)) === name))) continue;
    // Kept whole, whatever their form ("<X as Drop>::drop"): dropping one would make the list look shorter than it is.
    for (const f of a.ecosystem_specific?.affects?.functions ?? []) if (typeof f === 'string' && f.length < 500) out.add(f);
  }
  return [...out];
}

// A distribution's record of one CVE ("DEBIAN-CVE-2023-5678", "UBUNTU-CVE-…", "ALPINE-CVE-…") names that CVE
// in `upstream`, not in `aliases`: it is the same vulnerability, so the CVE (read from the record's own id,
// which is there even when its details could not be loaded) is one of its identifiers.
const PER_CVE = /^[A-Z][A-Z0-9]*-(CVE-\d{4}-\d{4,})$/;

/** All identifiers of a record (its own id, its aliases, and the CVE a per-CVE distribution record is about), CVE first. */
export function idsOf(rec) {
  const own = PER_CVE.exec(String(rec.id ?? ''));
  const ids = [...new Set([rec.id, ...(rec.aliases ?? []), ...(own ? [own[1]] : [])])];
  return ids.sort((a, b) => Number(CVE_RE.test(b)) - Number(CVE_RE.test(a)) || a.localeCompare(b));
}

/**
 * The CVEs a distribution advisory fixes ("ALSA-2024:0310", "RHSA-…", "DSA-…", "USN-…": listed in `upstream`).
 * An advisory may fix several: they are not its aliases, but it is exploited if one of them is.
 */
export function upstreamCves(rec) {
  return [...new Set((rec.upstream ?? []).filter((u) => typeof u === 'string' && CVE_RE.test(u)))];
}

/**
 * Groups the records affecting one component so that one vulnerability published by several databases
 * (for example a GitHub advisory and a PyPI advisory for the same CVE) is reported once.
 */
export function groupRecords(records) {
  const groups = [];
  for (const rec of records) {
    if (rec.withdrawn) continue;
    const ids = idsOf(rec);
    const hit = groups.filter((g) => ids.some((id) => g.ids.has(id)));
    const g = hit[0] ?? { ids: new Set(), records: [] };
    if (!hit.length) groups.push(g);
    for (const other of hit.slice(1)) {
      for (const id of other.ids) g.ids.add(id);
      g.records.push(...other.records);
      groups.splice(groups.indexOf(other), 1);
    }
    for (const id of ids) g.ids.add(id);
    g.records.push(rec);
  }
  return groups.map((g) => {
    const ids = [...g.ids].sort((a, b) => Number(CVE_RE.test(b)) - Number(CVE_RE.test(a)) || a.localeCompare(b));
    return { id: ids[0], ids, records: g.records };
  });
}
