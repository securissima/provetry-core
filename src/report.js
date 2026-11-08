// SPDX-License-Identifier: AGPL-3.0-only
// Reports: plain text for the terminal, Markdown for a pull request or your technical file, JSON, and SARIF
// for code-scanning tools.
import { TOOL } from './version.js';
import { humanDuration } from './clock.js';

// Advisory text comes from third parties: strip control characters (terminal escape sequences included).
const clean = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]+/g, ' ').trim();

const LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', none: 'NONE', unknown: 'UNKNOWN' };

const fixText = (f) => (f.fixed.length ? `fixed in ${f.fixed.join(', ')}` : 'no fixed version published');
const exploitText = (f) => {
  if (!f.exploited) return '';
  const by = [f.exploited.kev && `CISA KEV${f.exploited.kev.dateAdded ? ` since ${f.exploited.kev.dateAdded}` : ''}${f.exploited.kev.ransomware ? ', used in ransomware' : ''}`, f.exploited.euvd && `ENISA EUVD${f.exploited.euvd.euvd ? ` ${f.exploited.euvd.euvd}` : ''}`].filter(Boolean);
  return `exploited in the wild (${by.join('; ')})`;
};
// EPSS: probability of exploitation in the next 30 days, and the share of scored CVEs below it.
const pct = (x) => `${(x * 100).toFixed(x < 0.1 ? 2 : 1)}%`;
const epssText = (f) => (f.epss ? `EPSS ${pct(f.epss.score)} (top ${pct(Math.max(0.0001, 1 - f.epss.percentile))})` : '');
const compText = (f) => `${f.component.name}@${f.component.version}${f.component.direct ? '' : ' (transitive)'}`;

function header(r) {
  const p = r.product ? `${r.product.name}${r.product.version ? ` ${r.product.version}` : ''}` : 'project';
  return { p, comps: `${r.components.scanned} components scanned${r.components.devExcluded ? ` (${r.components.devExcluded} development dependencies left out)` : ''}` };
}

const NEXT_EXPLOITED =
  'A vulnerability exploited in the wild sits in a component you ship. Check now whether it can be reached in your product. ' +
  'If your product is affected and the vulnerability is being exploited, Article 14 of the CRA asks for an early warning within ' +
  '24 hours of becoming aware: run `provetry clock --since "<when you became aware>"` for the deadlines.';

export function toText(r) {
  const { p, comps } = header(r);
  const out = [`Provetry ${TOOL.version} · ${p} · ${comps}`, ''];
  for (const n of r.notes ?? []) out.push(`Note: ${n}`);
  for (const s of r.sources) if (!s.ok) out.push(s.optional ? `! ${s.name} unavailable (${s.note}): findings are not ranked by likelihood of exploitation.` : `! ${s.name} unavailable (${s.note}). Results are incomplete.`);
  if (r.sources.some((s) => !s.ok)) out.push('');
  if (!r.findings.length) {
    out.push(r.complete ? 'No known vulnerability in these components.' : 'No known vulnerability found, but some sources could not be checked.');
  } else {
    const c = r.counts;
    out.push(`${r.findings.length} known vulnerabilit${r.findings.length > 1 ? 'ies' : 'y'}: ${c.exploited} exploited in the wild · ${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low${c.unknown ? ` · ${c.unknown} unrated` : ''}`, '');
    for (const f of r.findings) {
      out.push(clean(`${f.exploited ? '!! ' : ''}${LABEL[f.severity]}${f.score !== null ? ` ${f.score}` : ''}  ${f.id}  ${compText(f)}`));
      if (f.summary) out.push(`   ${clean(f.summary)}`);
      const extra = [exploitText(f), epssText(f), fixText(f), f.vex ? `VEX: ${f.vex.status}` : '', f.ids.length > 1 ? `also ${f.ids.slice(1).join(', ')}` : ''].filter(Boolean);
      out.push(`   ${clean(extra.join(' · '))}`);
      out.push(`   ${f.url}`, '');
    }
    if (r.counts.exploited) out.push(NEXT_EXPLOITED, '');
  }
  if (r.suppressed.length) out.push(`${r.suppressed.length} more hidden by your VEX statements (not affected or fixed).`);
  return out.join('\n').trimEnd() + '\n';
}

const code = (s) => '`' + clean(s).replace(/`/g, "'").replace(/\|/g, '\\|') + '`';
const md = (s) => clean(s).replace(/[|\\`*_[\]<>]/g, (ch) => `\\${ch}`).replace(/\r?\n/g, ' ');

export function toMarkdown(r) {
  const { p, comps } = header(r);
  const out = [`# Vulnerability report: ${md(p)}`, '', `Generated ${r.generatedAt} by Provetry ${TOOL.version}. ${comps}.`, ''];
  out.push('Sources: ' + r.sources.map((s) => (s.ok ? s.name : `${s.name} (unavailable: ${md(s.note)})`)).join(', ') + '.', '');
  if (!r.complete) out.push('> **Incomplete:** at least one source could not be checked. Run the scan again before relying on this report.', '');
  for (const n of r.notes ?? []) out.push(`> **Note:** ${md(n)}`, '');
  if (!r.findings.length) {
    out.push('No known vulnerability in these components.', '');
  } else {
    const c = r.counts;
    out.push('| Exploited | Critical | High | Medium | Low | Unrated |', '|---|---|---|---|---|---|', `| ${c.exploited} | ${c.critical} | ${c.high} | ${c.medium} | ${c.low} | ${c.unknown} |`, '');
    out.push('| Vulnerability | Severity | Component | Fix | Exploited | EPSS |', '|---|---|---|---|---|---|');
    for (const f of r.findings) {
      out.push(`| [${md(f.id)}](${f.url}) | ${LABEL[f.severity]}${f.score !== null ? ` ${f.score}` : ''} | ${code(`${f.component.name}@${f.component.version}`)}${f.component.direct ? '' : ' (transitive)'} | ${md(fixText(f))} | ${f.exploited ? md(exploitText(f).replace(/^exploited in the wild /, '')) : ''} | ${f.epss ? pct(f.epss.score) : ''} |`);
    }
    out.push('');
    if (r.counts.exploited) out.push(`> ${NEXT_EXPLOITED}`, '');
  }
  if (r.suppressed.length) {
    out.push('## Declared not affected or fixed (VEX)', '', '| Vulnerability | Component | Status | Justification |', '|---|---|---|---|');
    for (const f of r.suppressed) out.push(`| ${md(f.id)} | ${code(`${f.component.name}@${f.component.version}`)} | ${f.vex.status} | ${md(f.vex.justification)} |`);
    out.push('');
  }
  return out.join('\n');
}

export const toJson = (r) => JSON.stringify(r, null, 2) + '\n';

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', none: 'note', unknown: 'warning' };

export function toSarif(r, { location = 'sbom.json' } = {}) {
  const rules = new Map();
  const results = [];
  for (const f of r.findings) {
    if (!rules.has(f.id)) {
      rules.set(f.id, {
        id: f.id,
        name: f.id,
        shortDescription: { text: f.summary || f.id },
        helpUri: f.url,
        properties: { tags: ['security', 'vulnerability'], ...(f.score !== null ? { 'security-severity': String(f.score) } : {}) },
      });
    }
    const file = f.component.sources[0] ?? location;
    results.push({
      ruleId: f.id,
      level: f.exploited ? 'error' : SARIF_LEVEL[f.severity],
      message: { text: `${f.id} in ${compText(f)}: ${[exploitText(f), epssText(f), fixText(f)].filter(Boolean).join('; ')}.` },
      locations: [{ physicalLocation: { artifactLocation: { uri: file } } }],
      partialFingerprints: { 'provetry/v1': `${f.id}|${f.component.purl}` },
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{ tool: { driver: { name: 'Provetry', version: TOOL.version, informationUri: 'https://github.com/Enigmacker/provetry-core', rules: [...rules.values()] } }, results }],
  };
}

export function clockText(c, now = new Date()) {
  const fmt = (d) => d.toISOString().replace('T', ' ').replace(/:\d\d\.\d+Z$/, ' UTC');
  const out = [`CRA Article 14 · ${c.kind === 'incident' ? 'severe incident' : 'actively exploited vulnerability'} · aware since ${fmt(c.awareAt)}`, ''];
  for (const s of c.steps) {
    const when = s.due ? `${fmt(s.due)}  (${humanDuration(s.due.getTime() - now.getTime())}${s.due.getTime() >= now.getTime() ? ' left' : ''})${s.note.startsWith('at the latest') ? ', ' + s.note : ''}` : s.note;
    out.push(`${s.step.padEnd(14)} ${s.article.padEnd(14)} ${when}`);
  }
  out.push('', 'Notify the CSIRT designated as coordinator and ENISA through the single reporting platform.', 'This tool computes dates; whether you must report is your own assessment.');
  return out.join('\n') + '\n';
}
