import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadEuvdExploited, euvdExploitedPage, EUVD_API } from '../src/vuln/euvd.js';
import { memoryCache } from '../src/cache.js';

// Answers shaped like ENISA's search: { items, total }, aliases as one string with a newline after each.
const item = (n) => ({ id: `EUVD-2026-${n}`, aliases: `CVE-2026-${n}\nGHSA-aaaa-bbbb-${String(n).padStart(4, '0')}\n`, exploitedSince: 'Nov 3, 2026, 12:00:00 AM' });
const TOTAL = 230;
const ALL = Array.from({ length: TOTAL }, (_, i) => item(1000 + i));
const ctxOf = (calls, answer) => ({
  cache: memoryCache(),
  fetchJson: async (url) => { calls.push(url); return answer(url); },
});
const search = (url) => {
  const m = /\/search\?exploited=true&size=(\d+)&page=(\d+)$/.exec(url);
  if (!m) return { status: 404, json: { message: 'No API endpoint at this path' } };
  const size = Number(m[1]), page = Number(m[2]);
  return { status: 200, json: { items: ALL.slice(page * size, page * size + size), total: TOTAL } };
};

test('EUVD: the exploited list is read from the search, page by page, 100 at a time', async () => {
  assert.equal(euvdExploitedPage(0), `${EUVD_API}/search?exploited=true&size=100&page=0`);
  const calls = [];
  const map = await loadEuvdExploited(ctxOf(calls, search));
  assert.deepEqual(calls, [0, 1, 2].map(euvdExploitedPage));
  assert.equal(map.size, TOTAL * 2, 'every CVE and GHSA alias');
  assert.deepEqual(map.get('CVE-2026-1000'), { euvd: 'EUVD-2026-1000', exploitedSince: 'Nov 3, 2026, 12:00:00 AM' });
  assert.equal(map.get('GHSA-aaaa-bbbb-1229').euvd, 'EUVD-2026-1229', 'last entry of the last page');
});

test('EUVD: read once a day, then from the cache', async () => {
  const calls = [];
  const ctx = ctxOf(calls, search);
  await loadEuvdExploited(ctx);
  const n = calls.length;
  assert.equal((await loadEuvdExploited(ctx)).size, TOTAL * 2);
  assert.equal(calls.length, n);
});

test('EUVD: an error or an unexpected answer is reported, not taken as an empty list', async () => {
  await assert.rejects(loadEuvdExploited(ctxOf([], () => ({ status: 404, json: { message: 'No API endpoint at this path' } }))), /HTTP 404/);
  await assert.rejects(loadEuvdExploited(ctxOf([], () => ({ status: 200, json: [item(1)] }))), /HTTP 200/);
  await assert.rejects(loadEuvdExploited(ctxOf([], () => ({ status: 200, json: { items: [], total: 0 } }))), /empty answer/);
});
