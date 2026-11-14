import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collect } from '../src/lockfiles/index.js';
import { scan, reachesThreshold } from '../src/scan.js';
import { memoryCache } from '../src/cache.js';
import { readVex, vexTemplate, purlCovers } from '../src/vex.js';
import { toText, toMarkdown, toSarif } from '../src/report.js';
import { severityOf, groupRecords, fixedVersions } from '../src/vuln/osv.js';

const root = new URL('./fixtures/proj', import.meta.url).pathname;

const AFFECTED = {
  'pkg:npm/lodash@4.17.20': [{ id: 'GHSA-35jh-r3h4-6jhm', modified: '2024-01-01T00:00:00Z' }],
  'pkg:npm/axios@1.6.0': [{ id: 'GHSA-wf5p-g6vw-rhxx', modified: '2024-01-01T00:00:00Z' }],
  'pkg:pypi/requests@2.31.0': [
    { id: 'GHSA-9wx4-h78v-vm56', modified: '2024-06-01T00:00:00Z' },
    { id: 'PYSEC-2024-60', modified: '2024-06-01T00:00:00Z' },
  ],
  'pkg:golang/golang.org/x/net@v0.17.0': [{ id: 'GO-2023-2102', modified: '2024-01-01T00:00:00Z' }],
  'pkg:composer/phpunit/phpunit@10.0.0': [{ id: 'GHSA-dev-only', modified: '2024-01-01T00:00:00Z' }],
};
const DETAILS = {
  'GHSA-35jh-r3h4-6jhm': {
    id: 'GHSA-35jh-r3h4-6jhm', aliases: ['CVE-2021-23337'], summary: 'Command Injection in lodash',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
  },
  'GHSA-wf5p-g6vw-rhxx': {
    id: 'GHSA-wf5p-g6vw-rhxx', aliases: ['CVE-2023-45857'], summary: 'Axios CSRF token exposure', database_specific: { severity: 'MODERATE' },
    affected: [{ package: { ecosystem: 'npm', name: 'axios' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0.8.1' }, { fixed: '1.6.0' }] }, { type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.6.0' }] }] }],
  },
  'GHSA-9wx4-h78v-vm56': {
    id: 'GHSA-9wx4-h78v-vm56', aliases: ['CVE-2024-35195'], summary: 'Requests Session verify=False persists',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N' }],
    affected: [{ package: { ecosystem: 'PyPI', name: 'requests' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.32.0' }] }] }],
  },
  'PYSEC-2024-60': {
    id: 'PYSEC-2024-60', aliases: ['CVE-2024-35195', 'GHSA-9wx4-h78v-vm56'], summary: '',
    affected: [{ package: { ecosystem: 'PyPI', name: 'Requests' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.32.0' }] }] }],
  },
  'GO-2023-2102': {
    id: 'GO-2023-2102', aliases: ['CVE-2023-44487', 'CVE-2023-39325', 'GHSA-4374-p667-p6c8'], summary: 'HTTP/2 rapid reset can cause excessive work in net/http',
    affected: [{ package: { ecosystem: 'Go', name: 'golang.org/x/net' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.17.0' }] }] }],
  },
};

function fakeFetch({ euvdStatus = 200, epssStatus = 200, calls = [] } = {}) {
  return async (url, opts = {}) => {
    calls.push(url);
    if (url.endsWith('/querybatch')) {
      return { status: 200, json: { results: opts.body.queries.map((q) => ({ vulns: AFFECTED[q.package.purl] ?? [] })) } };
    }
    const m = /\/vulns\/(.+)$/.exec(url);
    if (m) {
      const d = DETAILS[decodeURIComponent(m[1])];
      return d ? { status: 200, json: { ...d, modified: '2024-01-01T00:00:00Z' } } : { status: 404, json: null };
    }
    if (url.includes('known_exploited')) return { status: 200, json: { vulnerabilities: [{ cveID: 'CVE-2023-44487', dateAdded: '2023-10-10', knownRansomwareCampaignUse: 'Unknown' }, { cveID: 'CVE-2000-0001', knownRansomwareCampaignUse: 'Known' }] } };
    if (url.includes('euvdservices')) {
      return euvdStatus === 200 ? { status: 200, json: { items: [{ id: 'EUVD-2023-48495', aliases: 'CVE-2023-44487\nGHSA-qppj-fm5r-hxr3\n', exploitedSince: 'Oct 10, 2023' }], total: 1 } } : { status: euvdStatus, json: null };
    }
    if (url.includes('api.first.org/data/v1/epss')) {
      if (epssStatus !== 200) return { status: epssStatus, json: null };
      const asked = new URL(url).searchParams.get('cve').split(',');
      const scores = { 'CVE-2023-45857': ['0.42', '0.97'], 'CVE-2021-23337': ['0.0123', '0.79'], 'CVE-2023-44487': ['0.94', '0.999'] };
      return { status: 200, json: { data: asked.filter((c) => scores[c]).map((c) => ({ cve: c, epss: scores[c][0], percentile: scores[c][1], date: '2026-11-07' })) } };
    }
    throw new Error(`unexpected ${url}`);
  };
}

const ctxOf = (opts) => ({ fetchJson: fakeFetch(opts), cache: memoryCache(), now: () => new Date('2026-11-07T10:00:00Z') });

test('scan: exploited first, duplicates merged, dev dependencies left out', async () => {
  const { components } = await collect(root);
  const r = await scan(ctxOf(), components, { product: { name: 'demo' } });
  assert.equal(r.complete, true);
  assert.deepEqual(r.sources.map((s) => s.ok), [true, true, true, true]);
  // Exploited first; then likely to be exploited (axios, EPSS 42%) before a higher severity that is not.
  assert.deepEqual(r.findings.map((f) => f.id), ['CVE-2023-44487', 'CVE-2023-45857', 'CVE-2021-23337', 'CVE-2024-35195']);
  assert.deepEqual(r.findings[1].epss, { cve: 'CVE-2023-45857', score: 0.42, percentile: 0.97, date: '2026-11-07' });
  assert.equal(r.findings.find((f) => f.component.name === 'requests').epss, null, 'no score: nothing invented');
  const go = r.findings[0];
  assert.ok(go.exploited.kev && go.exploited.euvd, 'KEV and EUVD both flag it through its aliases');
  assert.equal(go.severity, 'unknown');
  const lodash = r.findings[2];
  assert.equal(lodash.severity, 'high');
  assert.equal(lodash.score, 7.2);
  assert.deepEqual(lodash.fixed, ['4.17.21']);
  const reqs = r.findings.find((f) => f.component.name === 'requests');
  assert.deepEqual(reqs.ids, ['CVE-2024-35195', 'GHSA-9wx4-h78v-vm56', 'PYSEC-2024-60']);
  assert.deepEqual(reqs.fixed, ['2.32.0']);
  assert.deepEqual(reqs.records, ['GHSA-9wx4-h78v-vm56', 'PYSEC-2024-60']);
  assert.equal(r.findings.find((f) => f.component.name === 'axios').severity, 'medium');
  assert.ok(!r.findings.some((f) => f.component.name === 'phpunit/phpunit'));
  assert.deepEqual(r.counts, { exploited: 1, critical: 0, high: 1, medium: 2, low: 0, unknown: 1 });
  assert.equal(reachesThreshold(r, 'exploited'), true);
  assert.equal(reachesThreshold(r, 'critical'), true, 'an exploited finding always reaches the threshold');
  assert.equal(reachesThreshold(r, 'none'), false);
});

test('scan: --include-dev and VEX suppression', async () => {
  const { components } = await collect(root);
  const vex = readVex({
    '@context': 'https://openvex.dev/ns/v0.2.0',
    statements: [
      { vulnerability: { name: 'CVE-2021-23337' }, products: [{ '@id': 'pkg:npm/lodash' }], status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' },
      { vulnerability: { name: 'CVE-2023-45857' }, products: [{ '@id': 'pkg:npm/express' }], status: 'not_affected' },
    ],
  });
  const r = await scan(ctxOf(), components, { vex, includeDev: true });
  assert.equal(r.suppressed.length, 1);
  assert.equal(r.suppressed[0].component.name, 'lodash');
  assert.equal(r.suppressed[0].vex.justification, 'vulnerable_code_not_in_execute_path');
  assert.ok(r.findings.some((f) => f.component.name === 'axios'), 'a statement about another product does not hide it');
  assert.ok(r.findings.some((f) => f.id === 'GHSA-dev-only'), 'dev dependencies are scanned on request, even without details');
  assert.equal(r.complete, false, 'a record whose details could not be loaded makes the result incomplete');
  assert.equal(r.answered, false, "missing details: not answered either");
});

test('scan: a failing source is reported, the others still answer', async () => {
  const { components } = await collect(root);
  const r = await scan(ctxOf({ euvdStatus: 503 }), components);
  assert.deepEqual(r.sources.find((s) => s.name === 'ENISA EUVD'), { name: 'ENISA EUVD', ok: false, note: 'HTTP 503' });
  assert.equal(r.answered, false);
  assert.equal(r.complete, false);
  assert.ok(r.findings[0].exploited.kev);
  assert.equal(r.findings[0].exploited.euvd, null);
  assert.match(toText(r), /ENISA EUVD unavailable/);
});

test('scan: offline runs answer from the cache and make no request', async () => {
  const { components } = await collect(root);
  const cache = memoryCache();
  const store = new Map();
  cache.get = (k) => store.get(k);
  cache.set = (k, v) => store.set(k, v);
  await scan({ fetchJson: fakeFetch(), cache }, components);
  const calls = [];
  const r = await scan({ fetchJson: fakeFetch({ calls }), cache, offline: true }, components);
  assert.equal(calls.length, 0);
  assert.equal(r.findings.length, 4);
  assert.equal(r.complete, true);
});

test('reports: text, Markdown and SARIF carry the essentials', async () => {
  const { components } = await collect(root);
  const r = await scan(ctxOf(), components, { product: { name: 'demo', version: '2.0' } });
  const text = toText(r);
  assert.match(text, /!! UNKNOWN {2}CVE-2023-44487 {2}golang\.org\/x\/net@v0\.17\.0 \(transitive\)/);
  assert.match(text, /exploited in the wild \(CISA KEV since 2023-10-10; ENISA EUVD EUVD-2023-48495\)/);
  assert.match(text, /Article 14/);
  const md = toMarkdown(r);
  assert.match(md, /^# Vulnerability report: demo 2\.0/);
  assert.match(md, /\| \[CVE-2021-23337\]\(https:\/\/osv\.dev\/vulnerability\/GHSA-35jh-r3h4-6jhm\) \| HIGH 7\.2 \|/);
  const sarif = toSarif(r);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 4);
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'svc/go.mod');
  assert.equal(new Set(sarif.runs[0].tool.driver.rules.map((x) => x.id)).size, sarif.runs[0].tool.driver.rules.length);
});

test('Markdown escapes what advisories contain', () => {
  const r = { generatedAt: 'now', product: { name: 'a|b' }, components: { scanned: 1, devExcluded: 0 }, sources: [], complete: true, counts: { exploited: 0, critical: 0, high: 1, medium: 0, low: 0, unknown: 0 }, suppressed: [],
    findings: [{ id: 'X-1', ids: ['X-1'], summary: '<script>', component: { name: 'p|q', version: '1', direct: true, sources: [] }, severity: 'high', score: null, fixed: ['1|2'], exploited: null, url: 'https://osv.dev/vulnerability/X-1' }] };
  const md = toMarkdown(r);
  assert.match(md, /demo|a\\\|b/);
  assert.ok(!/[^\\]\|q/.test(md.split('\n').find((l) => l.includes('p\\|q'))));
});

test('OSV helpers: severity fallbacks, fixed versions per package, alias grouping', () => {
  assert.deepEqual(severityOf({ id: 'x', database_specific: { severity: 'CRITICAL' } }), { rating: 'critical', score: null, vector: null });
  assert.equal(severityOf({ id: 'x', severity: [{ type: 'CVSS_V4', score: 'CVSS:4.0/AV:N' }] }).rating, 'unknown');
  assert.equal(severityOf({ id: 'x', affected: [{ ecosystem_specific: { severity: 'LOW' } }] }).rating, 'low');
  const rec = { affected: [{ package: { ecosystem: 'PyPI', name: 'Some_Pkg' }, ranges: [{ events: [{ fixed: '1.2' }] }] }, { package: { ecosystem: 'PyPI', name: 'other' }, ranges: [{ events: [{ fixed: '9' }] }] }] };
  assert.deepEqual(fixedVersions(rec, 'pkg:pypi/some-pkg@1.0'), ['1.2']);
  const g = groupRecords([{ id: 'A', aliases: ['B'] }, { id: 'C', aliases: [] }, { id: 'D', aliases: ['C', 'B'] }, { id: 'W', withdrawn: '2024', aliases: [] }]);
  assert.equal(g.length, 1);
  assert.deepEqual(g[0].ids, ['A', 'B', 'C', 'D']);
});

test('VEX: CycloneDX statements, purl coverage, and the template', () => {
  const st = readVex({ bomFormat: 'CycloneDX', components: [{ 'bom-ref': 'r1', purl: 'pkg:pypi/Requests@2.31.0' }], vulnerabilities: [{ id: 'CVE-2024-35195', analysis: { state: 'resolved' }, affects: [{ ref: 'r1' }] }] });
  assert.deepEqual(st, [{ ids: ['CVE-2024-35195'], products: ['pkg:pypi/Requests@2.31.0'], unresolved: false, status: 'fixed', justification: '' }]);
  assert.ok(purlCovers('pkg:pypi/Requests@2.31.0', 'pkg:pypi/requests@2.31.0'));
  assert.ok(!purlCovers('pkg:npm/a@1', 'pkg:npm/a@2'));
  assert.throws(() => readVex({}));
  const t = vexTemplate([{ id: 'CVE-1', ids: ['CVE-1', 'GHSA-1'], component: { purl: 'pkg:npm/a@1' } }], { now: new Date('2026-11-07T00:00:00Z') });
  assert.equal(t.statements[0].status, 'under_investigation');
  assert.deepEqual(t.statements[0].vulnerability, { name: 'CVE-1', aliases: ['GHSA-1'] });
  assert.equal(readVex(t).length, 1, 'the template reads back');
});

test('KEV: only "Known" marks ransomware use, not "Unknown"', async () => {
  const { loadKev } = await import('../src/vuln/kev.js');
  const kev = await loadKev(ctxOf());
  assert.equal(kev.get('CVE-2023-44487').ransomware, false);
  assert.equal(kev.get('CVE-2000-0001').ransomware, true);
});

test('terminal output strips escape sequences from advisory text', () => {
  const r = { generatedAt: 'now', product: null, components: { scanned: 1, devExcluded: 0 }, sources: [], complete: true, counts: { exploited: 0, critical: 0, high: 1, medium: 0, low: 0, unknown: 0 }, suppressed: [],
    findings: [{ id: 'X-1', ids: ['X-1'], summary: 'bad\u001b[2J\u001b]0;pwned\u0007 text', component: { name: 'p', version: '1', direct: true, sources: [] }, severity: 'high', score: null, fixed: [], exploited: null, url: 'u' }] };
  assert.ok(!/[\u001b\u0007]/.test(toText(r)));
  assert.ok(!/[\u001b\u0007]/.test(toMarkdown(r)));
});

test('scan: EPSS down is only a missing ranking aid, the scan stays complete', async () => {
  const { components } = await collect(root);
  const r = await scan(ctxOf({ epssStatus: 503 }), components);
  assert.equal(r.complete, true);
  assert.equal(r.sources.find((s) => s.name === 'FIRST EPSS').ok, false);
  assert.ok(r.findings.every((f) => f.epss === null));
  const off = await scan(ctxOf(), components, { epss: false });
  assert.ok(!off.sources.some((s) => s.name === 'FIRST EPSS'));
});

test('the exploited-vulnerability catalogues are exported', async () => {
  const core = await import('../src/index.js');
  assert.equal(typeof core.loadKev, 'function');
  assert.equal(typeof core.loadEuvdExploited, 'function');
  const kev = await core.loadKev(ctxOf());
  assert.ok(kev instanceof Map && kev.size > 0);
});

test('scan: operating-system packages of a release OSV does not cover are not asked about, and the scan is incomplete', async () => {
  const calls = [];
  const queries = [];
  const fetch = fakeFetch({ calls });
  const ctx = { fetchJson: async (url, opts) => { if (url.endsWith('/querybatch')) queries.push(...opts.body.queries); return fetch(url, opts); }, cache: memoryCache(), now: () => new Date('2026-11-07T10:00:00Z') };
  const components = [
    { type: 'deb', name: 'bash', version: '5.2', purl: 'pkg:deb/debian/bash@5.2', scope: 'required', sources: ['s'] },
    { type: 'deb', name: 'zsh', version: '5.9', purl: 'pkg:deb/debian/zsh@5.9?distro=debian-12', scope: 'required', sources: ['s'] },
    { type: 'npm', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20', scope: 'required', sources: ['s'] },
  ];
  const r = await scan(ctx, components, { euvd: false, epss: false });
  assert.deepEqual(queries.map((q) => q.package.purl ?? `${q.package.ecosystem}/${q.package.name}`), ['Debian:12/zsh', 'pkg:npm/lodash@4.17.20']);
  assert.equal(r.complete, false);
  assert.match(r.sources.find((s) => s.name === 'Operating-system packages').note, /1 not looked up/);
  assert.equal(r.answered, true, 'a lasting gap: every source that can answer did');
});

test('scan: Syft-style Alpine purls are looked up; RPM packages are said not to be', async () => {
  const queries = [];
  const fetch = fakeFetch();
  const ctx = { fetchJson: async (url, opts) => { if (url.endsWith('/querybatch')) queries.push(...opts.body.queries); return fetch(url, opts); }, cache: memoryCache(), now: () => new Date('2026-11-07T10:00:00Z') };
  const components = [
    { type: 'apk', name: 'musl', version: '1.2.4-r2', purl: 'pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1&upstream=musl', scope: 'required', sources: ['s'] },
    { type: 'rpm', name: 'bash', version: '5.1.8-6.el9', purl: 'pkg:rpm/redhat/bash@5.1.8-6.el9?arch=x86_64&distro=rhel-9.3', scope: 'required', sources: ['s'] },
  ];
  const r = await scan(ctx, components, { euvd: false, epss: false });
  assert.deepEqual(queries, [{ package: { name: 'musl', ecosystem: 'Alpine:v3.19' }, version: '1.2.4-r2' }]);
  assert.equal(r.complete, false);
  assert.match(r.sources.find((s) => s.name === 'Operating-system packages').note, /pkg:rpm\/redhat\/bash/);
});
