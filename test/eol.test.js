import { test } from 'node:test';
import assert from 'node:assert/strict';
import { endOfLife, cycleOf, purlBase } from '../src/vuln/eol.js';
import { loadEpss, epssOf } from '../src/vuln/epss.js';
import { memoryCache } from '../src/cache.js';

const IDS = { schema_version: '1.2.0', result: [
  { identifier: 'pkg:npm/%40angular/core', product: { name: 'angular', uri: 'x' } },
  { identifier: 'pkg:pypi/django', product: { name: 'django', uri: 'x' } },
  { identifier: 'pkg:npm/bad', product: { name: '../etc', uri: 'x' } },
  { identifier: 'pkg:npm/dots', product: { name: '..', uri: 'x' } },
  { identifier: 'pkg:npm/flaky', product: { name: 'flaky', uri: 'x' } },
] };
const PRODUCTS = {
  angular: { result: { label: 'Angular', releases: [
    { name: '17', eolFrom: '2025-05-15', isEol: true, isMaintained: false, latest: { name: '17.3.12' } },
    { name: '20', eolFrom: '2026-11-28', isEol: false, isMaintained: true, latest: { name: '20.3.4' } },
  ] } },
  django: { result: { label: 'Django', releases: [
    { name: '5.2', eolFrom: '2028-04-30', isEol: false, latest: { name: '5.2.8' } },
    { name: '5', eolFrom: '2020-01-01', isEol: true },
    { name: '4.2', eolFrom: '2026-04-30', isEol: true, latest: { name: '4.2.26' } },
  ] } },
};
const fetchOf = (calls = []) => async (url) => {
  calls.push(url);
  if (url.endsWith('/identifiers/purl')) return { status: 200, json: IDS };
  const m = /\/products\/([^/]+)$/.exec(url);
  if (m && PRODUCTS[m[1]]) return { status: 200, json: PRODUCTS[m[1]] };
  return { status: 404, json: null };
};

test('purl base: version, qualifiers and encoding do not prevent a match', () => {
  assert.equal(purlBase('pkg:npm/%40angular/core@17.3.0?foo=bar#x'), 'pkg:npm/@angular/core');
  assert.equal(purlBase('pkg:pypi/Django@4.2.1'), 'pkg:pypi/django');
  assert.equal(purlBase('pkg:golang/github.com/a/b'), 'pkg:golang/github.com/a/b');
});

test('release cycle: the longest matching prefix, at a dot', () => {
  const list = PRODUCTS.django.result.releases;
  assert.equal(cycleOf(list, '5.2.3').name, '5.2');
  assert.equal(cycleOf(list, '4.2.0').name, '4.2');
  assert.equal(cycleOf(list, '5.1.0').name, '5');
  assert.equal(cycleOf(list, '42.0'), null, '4.2 is not a prefix of 42.0');
  assert.equal(cycleOf(PRODUCTS.angular.result.releases, 'v17.3.0').name, '17');
});

test('end of life: compared with the product support period; unknown components are not guessed', async () => {
  const calls = [];
  const comps = [
    { purl: 'pkg:npm/%40angular/core@17.3.0', name: '@angular/core', version: '17.3.0' },
    { purl: 'pkg:npm/@angular/core@20.1.0', name: '@angular/core', version: '20.1.0' },
    { purl: 'pkg:pypi/django@5.2.3', name: 'django', version: '5.2.3' },
    { purl: 'pkg:npm/left-pad@1.3.0', name: 'left-pad', version: '1.3.0' },
    { purl: 'pkg:npm/bad@1.0.0', name: 'bad', version: '1.0.0' },
  ];
  comps.push({ purl: 'pkg:npm/dots@1.0.0', name: 'dots', version: '1.0.0' }, { purl: 'pkg:npm/flaky@1.0.0', name: 'flaky', version: '1.0.0' });
  const r = await endOfLife({ fetchJson: fetchOf(calls), cache: memoryCache() }, comps, { supportUntil: '2031-12-31', today: new Date('2026-11-08T00:00:00Z') });
  assert.equal(r.known, 4, 'left-pad is not known; the bad product names are refused');
  assert.deepEqual(r.failed, ['flaky'], 'a product that did not answer is reported, not silently dropped');
  assert.deepEqual(r.results.map((x) => `${x.name}@${x.version}:${x.cycle}:${x.isEol}:${x.beforeSupportEnd}`), [
    '@angular/core@17.3.0:17:true:true', '@angular/core@20.1.0:20:false:true', 'django@5.2.3:5.2:false:true',
  ]);
  assert.ok(!calls.some((u) => u.includes('..')), 'a product name from the list never builds a path');
  assert.equal(r.results[0].latest, '17.3.12');
  const short = await endOfLife({ fetchJson: fetchOf(), cache: memoryCache() }, comps.slice(2, 3), { supportUntil: '2027-06-30', today: new Date('2026-11-08T00:00:00Z') });
  assert.equal(short.results[0].beforeSupportEnd, false);
});

test('EPSS: batches of 100, unscored CVEs remembered as such, best score of the aliases', async () => {
  const calls = [];
  const fetchJson = async (url) => {
    calls.push(url);
    const asked = new URL(url).searchParams.get('cve').split(',');
    return { status: 200, json: { data: asked.filter((c) => c.endsWith('1')).map((c) => ({ cve: c, epss: '0.5', percentile: '0.99', date: '2026-11-07' })) } };
  };
  const cves = Array.from({ length: 150 }, (_, i) => `CVE-2026-${10000 + i}`);
  const ctx = { fetchJson, cache: memoryCache() };
  const m = await loadEpss(ctx, [...cves, 'GHSA-xxxx', 'CVE-2026-10001']);
  assert.equal(calls.length, 2);
  assert.equal(m.size, 15);
  await loadEpss(ctx, cves);
  assert.equal(calls.length, 2, 'scored and unscored CVEs both come from the cache the second time');
  assert.deepEqual(m.missed, []);
  const half = await loadEpss({ fetchJson: async (url) => (url.includes('10000') ? { status: 503, json: null } : fetchJson(url)), cache: memoryCache() }, cves);
  assert.equal(half.missed.length, 100, 'the failed batch is reported as unknown');
  const off = await loadEpss({ ...ctx, offline: true }, [...cves.slice(0, 3), 'CVE-2030-0001']);
  assert.equal(off.size, 1);
  assert.deepEqual(off.missed, ['CVE-2030-0001'], 'offline: cached scores kept, the rest unknown');
  m.set('CVE-1999-0001', { score: 0.9, percentile: 1, date: null });
  assert.equal(epssOf(m, ['GHSA-x', 'CVE-2026-10001', 'CVE-1999-0001']).cve, 'CVE-1999-0001');
  assert.equal(epssOf(m, ['CVE-2026-10000']), null);
});
