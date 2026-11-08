// SPDX-License-Identifier: AGPL-3.0-only
// End of life of the components you ship, from endoflife.date (https://endoflife.date), which maps package
// URLs to products and gives, for each release cycle, when it stops receiving security fixes.
//
// Why it matters for the CRA: a manufacturer must handle the vulnerabilities of its product for the whole
// support period (Article 13(8)) and exercise due diligence on third-party components (Article 13(5)). A
// component whose own support ends before yours will stop getting fixes while you still owe them.
//
// Only components that endoflife.date knows by package URL are checked: most libraries are not there
// (they have no published support policy). Nothing is guessed for the others.
import { cacheGet, cacheSet, getJson, mapLimit } from '../util.js';

export const EOL_API = 'https://endoflife.date/api/v1';
const MAX_AGE = 24 * 3600;

/** The package URL without version, qualifiers or subpath, decoded and lower-case, to compare two of them. */
export function purlBase(purl) {
  const s = String(purl ?? '').split('#')[0].split('?')[0];
  const at = s.lastIndexOf('@');
  const slash = s.lastIndexOf('/');
  const base = at > slash ? s.slice(0, at) : s;
  try { return decodeURIComponent(base).toLowerCase(); } catch { return base.toLowerCase(); }
}

async function identifiers(ctx) {
  const cached = cacheGet(ctx, 'eol:purl', MAX_AGE);
  if (cached) return new Map(Object.entries(cached));
  const { status, json } = await getJson(ctx, `${EOL_API}/identifiers/purl`);
  if (status !== 200 || !Array.isArray(json?.result)) throw new Error(`HTTP ${status}`);
  const obj = {};
  for (const r of json.result) {
    const name = r?.product?.name;
    if (typeof r?.identifier === 'string' && typeof name === 'string' && /^[a-z0-9._-]+$/i.test(name)) obj[purlBase(r.identifier)] = name;
  }
  cacheSet(ctx, 'eol:purl', obj);
  return new Map(Object.entries(obj));
}

async function releases(ctx, product) {
  const key = `eol:product:${product}`;
  const cached = cacheGet(ctx, key, MAX_AGE);
  if (cached) return cached;
  const { status, json } = await getJson(ctx, `${EOL_API}/products/${encodeURIComponent(product)}`);
  if (status !== 200 || !Array.isArray(json?.result?.releases)) throw new Error(`HTTP ${status}`);
  const date = (d) => (typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d) ? d : null);
  const list = json.result.releases.filter((r) => typeof r?.name === 'string').map((r) => ({
    name: r.name, eolFrom: date(r.eolFrom), isEol: r.isEol === true, isMaintained: r.isMaintained !== false, latest: typeof r.latest?.name === 'string' ? r.latest.name : null,
  }));
  const value = { label: typeof json.result.label === 'string' ? json.result.label : product, releases: list };
  cacheSet(ctx, key, value);
  return value;
}

/** The release cycle a version belongs to: the longest cycle name that is the version or a prefix of it at a dot. */
export function cycleOf(list, version) {
  const v = String(version ?? '').replace(/^v(?=\d)/, '');
  let best = null;
  for (const r of list) {
    const n = r.name.replace(/^v(?=\d)/, '');
    if ((v === n || v.startsWith(`${n}.`) || v.startsWith(`${n}-`) || v.startsWith(`${n}+`)) && (!best || n.length > best.name.length)) best = r;
  }
  return best;
}

/**
 * For each component endoflife.date knows: its release cycle and when that cycle stops being supported.
 * `supportUntil` (YYYY-MM-DD) is the end of your own product's support period: a component whose end of
 * life comes earlier is flagged `beforeSupportEnd`.
 * @returns {Promise<{ results: object[], checked: number, known: number }>}
 */
export async function endOfLife(ctx, components, { supportUntil = null, today = new Date() } = {}) {
  const ids = await identifiers(ctx);
  const day = today.toISOString().slice(0, 10);
  const matched = components.map((c) => ({ c, product: ids.get(purlBase(c.purl)) })).filter((m) => m.product);
  const products = [...new Set(matched.map((m) => m.product))].slice(0, 100);
  const data = new Map();
  await mapLimit(products, 4, async (p) => {
    try { data.set(p, await releases(ctx, p)); } catch (e) { if (e.code === 'OFFLINE') throw e; }
  });
  const results = [];
  for (const { c, product } of matched) {
    const d = data.get(product);
    if (!d) continue;
    const cycle = cycleOf(d.releases, c.version);
    if (!cycle) continue;
    const eolFrom = cycle.eolFrom;
    results.push({
      purl: c.purl, name: c.name, version: c.version, product, label: d.label, cycle: cycle.name, eolFrom,
      // endoflife.date sometimes says a cycle is over without a date: trust its flag then.
      isEol: eolFrom ? eolFrom <= day : cycle.isEol,
      beforeSupportEnd: Boolean(supportUntil && eolFrom && eolFrom < supportUntil),
      latest: cycle.latest,
    });
  }
  results.sort((a, b) => Number(b.isEol) - Number(a.isEol) || (a.eolFrom ?? '9999').localeCompare(b.eolFrom ?? '9999') || a.name.localeCompare(b.name));
  return { results, checked: components.length, known: matched.length };
}
