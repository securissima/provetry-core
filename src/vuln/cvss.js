// SPDX-License-Identifier: AGPL-3.0-only
// CVSS 3.0 / 3.1 base score from a vector string (FIRST specification, section 7). CVSS 4.0 vectors are not
// computed here: their severity comes from the advisory instead.
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

/** CVSS 3.1 "Roundup": the smallest number, to one decimal place, equal to or higher than its input. */
export function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

/** Returns the base score (0–10) of a CVSS 3.x vector, or null if the vector is not a complete 3.x vector. */
export function cvss3Score(vector) {
  const m = /^CVSS:3\.[01]\/(.+)$/.exec(String(vector ?? '').trim());
  if (!m) return null;
  const v = Object.fromEntries(m[1].split('/').map((p) => p.split(':')));
  for (const k of ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']) if (!v[k]) return null;
  const changed = v.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[v.PR];
  const [av, ac, ui, c, i, a] = [W.AV[v.AV], W.AC[v.AC], W.UI[v.UI], W.CIA[v.C], W.CIA[v.I], W.CIA[v.A]];
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return changed ? roundup(Math.min(1.08 * (impact + expl), 10)) : roundup(Math.min(impact + expl, 10));
}

/** Qualitative rating for a CVSS score. */
export function ratingOf(score) {
  if (score === null || score === undefined) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'none';
}
