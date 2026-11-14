// SPDX-License-Identifier: AGPL-3.0-only
// Puts it together: components (from lock files or an SBOM) → known vulnerabilities (OSV) → which of them are
// exploited in the wild (CISA KEV, ENISA EUVD) → how likely the others are to be (FIRST EPSS) → your VEX
// statements → a prioritized list.
import { queryPurls, loadDetails, groupRecords, severityOf, fixedVersions, affectedFunctions } from './vuln/osv.js';
import { loadKev } from './vuln/kev.js';
import { loadEuvdExploited } from './vuln/euvd.js';
import { loadEpss, epssOf, EPSS_LIKELY } from './vuln/epss.js';
import { vexFor } from './vex.js';
import { osvQueryable, osvOsPackage } from './purl.js';

const RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0, unknown: 0 };

/**
 * @param {object} ctx { fetchJson, cache, offline?, now? }
 * @param {import('./lockfiles/index.js').Component[]} components
 * @param {{ product?: { name: string, version?: string }, vex?: object[], includeDev?: boolean, euvd?: boolean, epss?: boolean }} [opts]
 */
export async function scan(ctx, components, opts = {}) {
  const { vex = [], includeDev = false, euvd = true, epss: withEpss = true } = opts;
  const now = ctx.now?.() ?? new Date();
  const scanned = components.filter((c) => includeDev || c.scope !== 'dev');
  const sources = [];

  let affected = new Map();
  try {
    // Operating-system packages of a release OSV does not cover are not asked about: a query by bare purl
    // would match advisories of other releases.
    affected = await queryPurls(ctx, scanned.map((c) => c.purl).filter(osvQueryable));
    sources.push({ name: 'OSV.dev', ok: true });
  } catch (e) {
    sources.push({ name: 'OSV.dev', ok: false, note: e.code ?? e.message });
  }
  const unlooked = scanned.filter((c) => !osvQueryable(c.purl));
  // A lasting gap, not a source that failed to answer: trying again changes nothing.
  if (unlooked.length) sources.push({ name: 'Operating-system packages', ok: false, lasting: true, note: `${unlooked.length} not looked up: no public advisory database covers their release (e.g. ${unlooked[0].purl.split('?')[0]})` });
  // A derivative's packages (pkg:deb/raspbian/…?distro=debian-12) are looked up as its parent's: approximate,
  // as its own packages are not covered and its rebuilt versions compare only roughly with the parent's fixes.
  const derived = scanned.filter((c) => { const os = osvQueryable(c.purl) && osvOsPackage(c.purl); return os && os.family !== String(c.purl).split('/')[1]?.toLowerCase(); });
  if (derived.length) {
    const as = [...new Set(derived.map((c) => `${String(c.purl).split('/')[1]} as ${osvOsPackage(c.purl).ecosystem}`))].join(', ');
    sources.push({ name: 'Derivative distributions', ok: false, lasting: true, note: `${derived.length} looked up approximately (${as}): their own packages are not covered, and rebuilt versions compare only roughly with the parent's fixes` });
  }
  const refs = [...affected.values()].flat();
  const details = await loadDetails(ctx, refs);
  const missingDetails = new Set(refs.map((r) => r.id).filter((id) => !details.has(id)));

  let kev = new Map();
  try {
    kev = await loadKev(ctx);
    sources.push({ name: 'CISA KEV', ok: true });
  } catch (e) {
    sources.push({ name: 'CISA KEV', ok: false, note: e.code ?? e.message });
  }
  let eu = new Map();
  if (euvd) {
    try {
      eu = await loadEuvdExploited(ctx);
      sources.push({ name: 'ENISA EUVD', ok: true });
    } catch (e) {
      sources.push({ name: 'ENISA EUVD', ok: false, note: e.code ?? e.message });
    }
  }

  let epss = new Map();
  if (withEpss) {
    const cves = [...details.values()].flatMap((r) => [r.id, ...(r.aliases ?? [])]);
    try {
      epss = await loadEpss(ctx, cves);
      // Partial: some scores are unknown (a batch failed); keepers of earlier scores should keep them.
      sources.push({ name: 'FIRST EPSS', ok: true, ...(epss.missed?.length ? { partial: true, note: `${epss.missed.length} CVE${epss.missed.length > 1 ? 's' : ''} not scored this time` } : {}) });
    } catch (e) {
      // Only a ranking aid: without it nothing is missed, so the scan is still complete.
      sources.push({ name: 'FIRST EPSS', ok: false, optional: true, note: e.code ?? e.message });
    }
  }

  const findings = [];
  const suppressed = [];
  for (const c of scanned) {
    const list = affected.get(c.purl) ?? [];
    const records = list.map((r) => details.get(r.id) ?? { id: r.id, aliases: [], summary: '' });
    for (const g of groupRecords(records)) {
      const sev = g.records.map(severityOf).sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || RANK[b.rating] - RANK[a.rating])[0];
      const kevId = g.ids.find((id) => kev.has(id));
      const euId = g.ids.find((id) => eu.has(id));
      const kevHit = kevId ? kev.get(kevId) : null;
      const euHit = euId ? eu.get(euId) : null;
      // Lead with the identifier under which the vulnerability is known to be exploited.
      const lead = kevId ?? euId ?? g.id;
      const finding = {
        id: lead,
        ids: [lead, ...g.ids.filter((id) => id !== lead)],
        summary: g.records.map((r) => r.summary).find(Boolean) ?? '',
        component: { type: c.type, name: c.name, version: c.version, purl: c.purl, scope: c.scope, direct: !!c.direct, sources: c.sources ?? [] },
        severity: sev.rating,
        score: sev.score,
        vector: sev.vector,
        fixed: [...new Set(g.records.flatMap((r) => fixedVersions(r, c.purl)))],
        // The affected functions, when the advisory database names them (RustSec): used by reach.
        functions: [...new Set(g.records.flatMap((r) => affectedFunctions(r, c.purl)))],
        exploited: kevHit || euHit ? { kev: kevHit, euvd: euHit } : null,
        epss: epssOf(epss, g.ids),
        detailsMissing: g.records.every((r) => missingDetails.has(r.id)),
        // The OSV records behind it (their own ids, stable even when an advisory's aliases change).
        records: g.records.map((r) => r.id).sort(),
        url: `https://osv.dev/vulnerability/${encodeURIComponent(g.records[0].id)}`,
        vex: null,
      };
      const st = vexFor(vex, finding);
      if (st) finding.vex = { status: st.status, justification: st.justification };
      (st && (st.status === 'not_affected' || st.status === 'fixed') ? suppressed : findings).push(finding);
    }
  }
  findings.sort(compareFindings);
  const counts = { exploited: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of findings) {
    if (f.exploited) counts.exploited++;
    counts[f.severity === 'none' ? 'low' : f.severity]++;
  }
  return {
    tool: 'provetry',
    generatedAt: now.toISOString(),
    product: opts.product ?? null,
    components: { total: components.length, scanned: scanned.length, devExcluded: components.length - scanned.length },
    sources,
    complete: sources.every((s) => s.ok || s.optional) && missingDetails.size === 0,
    // Every source that can answer did: what was looked up is current, whatever lasting gap remains
    // (a service may then clear findings that are gone, and need not try again soon).
    answered: sources.every((s) => s.ok || s.optional || s.lasting) && missingDetails.size === 0,
    counts,
    findings,
    suppressed,
  };
}

const likely = (f) => (f.epss?.score ?? 0) >= EPSS_LIKELY;

/** Exploited first, then likely to be exploited (EPSS ≥ 10%), then by severity. */
export function compareFindings(a, b) {
  return (
    Number(!!b.exploited) - Number(!!a.exploited) ||
    Number(likely(b)) - Number(likely(a)) ||
    RANK[b.severity] - RANK[a.severity] ||
    (b.score ?? -1) - (a.score ?? -1) ||
    Number(b.component.direct) - Number(a.component.direct) ||
    a.component.name.localeCompare(b.component.name) ||
    a.id.localeCompare(b.id)
  );
}

/** True when at least one finding reaches the threshold: exploited | critical | high | medium | low | any. */
export function reachesThreshold(result, threshold) {
  if (!threshold || threshold === 'none') return false;
  if (threshold === 'exploited') return result.findings.some((f) => f.exploited);
  if (threshold === 'any') return result.findings.length > 0;
  const min = RANK[threshold];
  if (min === undefined) throw new Error(`unknown threshold: ${threshold}`);
  return result.findings.some((f) => f.exploited || RANK[f.severity] >= min);
}
