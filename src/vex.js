// SPDX-License-Identifier: AGPL-3.0-only
// VEX: your own statements about whether a known vulnerability actually affects your product
// ("not affected: the vulnerable function is never called"). Provetry reads OpenVEX and CycloneDX VEX,
// hides what you have declared not affected or fixed, and can write a starting OpenVEX file.
import { parsePurl, fullName } from './purl.js';
import { TOOL } from './version.js';

const STATUS = { not_affected: 'not_affected', fixed: 'fixed', affected: 'affected', under_investigation: 'under_investigation' };
const CDX_STATE = { not_affected: 'not_affected', false_positive: 'not_affected', resolved: 'fixed', resolved_with_pedigree: 'fixed', exploitable: 'affected', in_triage: 'under_investigation' };

const isPurl = (p) => typeof p === 'string' && p.startsWith('pkg:');
const idOf = (p) => (typeof p === 'string' ? p : p?.identifiers?.purl ?? p?.['@id']);

/**
 * The component purls a statement is about. A product with subcomponents is about those subcomponents
 * (OpenVEX: "this vulnerability in lodash, inside my application"). A statement none of whose products can be
 * matched to a component is about nothing here: never about everything.
 */
function productsOf(list) {
  const items = Array.isArray(list) ? list : [];
  const purls = [];
  for (const p of items) {
    const subs = Array.isArray(p?.subcomponents) ? p.subcomponents.map(idOf).filter(isPurl) : [];
    if (subs.length) purls.push(...subs);
    else if (isPurl(idOf(p))) purls.push(idOf(p));
  }
  // A statement that names no product at all is about nothing here either: OpenVEX requires products, and
  // a statement hiding a vulnerability everywhere is too broad to apply silently.
  return { products: purls, unresolved: purls.length === 0 };
}

/** Parses an OpenVEX or CycloneDX VEX document into statements { ids, products: purl[] , unresolved, status, justification }. */
export function readVex(json) {
  if (Array.isArray(json?.statements)) {
    return json.statements
      .map((s) => ({
        ids: [s.vulnerability?.name, s.vulnerability?.['@id'], ...(s.vulnerability?.aliases ?? [])].filter(Boolean),
        ...productsOf(s.products),
        status: STATUS[s.status] ?? null,
        justification: s.justification ?? s.impact_statement ?? '',
      }))
      .filter((s) => s.ids.length && s.status);
  }
  if (json?.bomFormat === 'CycloneDX' && Array.isArray(json.vulnerabilities)) {
    const refs = new Map((json.components ?? []).map((c) => [c['bom-ref'], c.purl]));
    return json.vulnerabilities
      .map((v) => ({
        ids: [v.id, ...(v.references ?? []).map((r) => r.id)].filter(Boolean),
        ...productsOf((v.affects ?? []).map((a) => refs.get(a.ref) ?? a.ref)),
        status: CDX_STATE[v.analysis?.state] ?? null,
        justification: v.analysis?.justification ?? v.analysis?.detail ?? '',
      }))
      .filter((s) => s.ids.length && s.status);
  }
  throw new Error('not an OpenVEX or CycloneDX VEX document');
}

/** True when a statement's product purl designates this component (a purl without version covers all versions). */
export function purlCovers(statementPurl, componentPurl) {
  const a = parsePurl(statementPurl);
  const b = parsePurl(componentPurl);
  if (!a || !b) return false;
  const n = (p) => (p.type === 'pypi' ? fullName(p).toLowerCase().replace(/[-_.]+/g, '-') : fullName(p));
  return a.type === b.type && n(a) === n(b) && (!a.version || a.version === b.version);
}

/** The statement that applies to a finding; null when none does. */
export function vexFor(statements, finding) {
  const ids = new Set(finding.ids);
  const matching = statements.filter((s) => !s.unresolved && s.ids.some((id) => ids.has(id)) && (s.products.some((p) => purlCovers(p, finding.component.purl))));
    return matching[0] ?? null;
}

/** An OpenVEX document with one "under_investigation" statement per finding, to be completed by you. */
export function vexTemplate(findings, { author = 'Unknown', now = new Date() } = {}) {
  const ts = now.toISOString();
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `https://provetry.com/vex/${ts}`,
    author,
    timestamp: ts,
    version: 1,
    tooling: `${TOOL.name}/${TOOL.version}`,
    statements: findings.map((f) => ({
      vulnerability: { name: f.id, ...(f.ids.length > 1 ? { aliases: f.ids.slice(1) } : {}) },
      products: [{ '@id': f.component.purl }],
      status: 'under_investigation',
    })),
  };
}
