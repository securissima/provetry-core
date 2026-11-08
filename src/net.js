// SPDX-License-Identifier: AGPL-3.0-only
// The only module that goes on the network. Every request has a timeout and a size limit, and names the tool.
import { VERSION } from './version.js';

const UA = `provetry/${VERSION} (+https://provetry.com)`;

/**
 * Fetches JSON. Returns { status, json }. Never throws for an HTTP status; throws on network failure or timeout.
 * @param {string} url
 * @param {{ method?: string, body?: unknown, timeoutMs?: number, maxBytes?: number, authorization?: string }} [opts]
 * With `authorization`, redirects are refused: the credential goes to the address given and nowhere else.
 */
export async function fetchJson(url, { method = 'GET', body, timeoutMs = 30_000, maxBytes = 64 * 1024 * 1024, authorization } = {}) {
  const res = await fetch(url, {
    method,
    headers: { 'user-agent': UA, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}), ...(authorization ? { authorization } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeoutMs),
    redirect: authorization ? 'error' : 'follow',
  });
  const len = Number(res.headers.get('content-length') ?? 0);
  if (len > maxBytes) throw new Error(`response too large from ${new URL(url).host}`);
  const reader = res.body?.getReader();
  const chunks = [];
  let total = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`response too large from ${new URL(url).host}`);
      }
      chunks.push(value);
    }
  }
  const text = Buffer.concat(chunks).toString('utf8');
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

/** The default context: real network and a file cache. Tests pass their own. */
export async function defaultContext({ cache = true } = {}) {
  const { fileCache } = await import('./cache.js');
  return { fetchJson, cache: cache ? fileCache() : null, now: () => new Date() };
}
