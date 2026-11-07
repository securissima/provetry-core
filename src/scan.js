// SPDX-License-Identifier: AGPL-3.0-only
// Puts it together: components (from lock files or an SBOM) → known vulnerabilities (OSV) → which of them are
// exploited in the wild (CISA KEV, ENISA EUVD) → your VEX statements → a prioritized list.
import { queryPurls, loadDetails, groupRecords, severityOf, fixedVersions } from './vuln/osv.js';
import { loadKev } from './vuln/kev.js';
import { loadEuvdExploited } from './vuln/euvd.js';
import { vexFor } from './vex.js';

const RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0, unknown: 0 };

/**
 * @param {object} ctx { fetchJson, cache, offline?, now? }
 * @param {import('./lockfiles/index.js').Component[]} components
 * @param {{ product?: { name: string, version?: string }, vex?: object[], includeDev?: boolean, euvd?: boolean }} [opts]
 */
export async function scan(ctx, components, opts = {}) {
  const { vex = [], includeDev = false, euvd = true } = opts;
  const now = ctx.now?.() ?? new Date();
  const scanned = components.filter((c) => includeDev || c.scope !== 'dev');
  const sources = [];

  let affected = new Map();
  try {
    affected = await queryPurls(ctx, scanned.map((c) => c.purl));
    sources.push({ name: 'OSV.dev', ok: true });
  } catch (e) {
    sources.push({ name: 'OSV.dev', ok: false, note: e.code ?? e.message });
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
        exploited: kevHit || euHit ? { kev: kevHit, euvd: euHit } : null,
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
    complete: sources.every((s) => s.ok) && missingDetails.size === 0,
    counts,
    findings,
    suppressed,
  };
}

export function compareFindings(a, b) {
  return (
    Number(!!b.exploited) - Number(!!a.exploited) ||
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
