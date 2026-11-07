// SPDX-License-Identifier: AGPL-3.0-only

/** Runs fn over items with at most `limit` calls in flight. Results keep the input order. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

export const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

/** Reads from the cache, ignoring age when the run is offline. */
export function cacheGet(ctx, key, maxAgeSec) {
  return ctx.cache?.get(key, ctx.offline ? Infinity : maxAgeSec);
}

export function cacheSet(ctx, key, value) {
  ctx.cache?.set(key, value);
}

/** Fetches through ctx, refusing when the run is offline. */
export async function getJson(ctx, url, opts) {
  if (ctx.offline) throw Object.assign(new Error('offline'), { code: 'OFFLINE' });
  return ctx.fetchJson(url, opts);
}
