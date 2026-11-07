// SPDX-License-Identifier: AGPL-3.0-only
// A small file cache for public vulnerability data (catalogues, advisories), so that repeated scans stay quick
// and polite to the services. Entries are keyed by a hash; the only trace of your project is which package
// versions were looked up, and what OSV answered for them.
import { mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function cacheDir() {
  return process.env.PROVETRY_CACHE_DIR || join(process.env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'provetry');
}

export function fileCache(dir = cacheDir()) {
  const file = (key) => join(dir, `${createHash('sha256').update(key).digest('hex').slice(0, 32)}.json`);
  return {
    get(key, maxAgeSec) {
      try {
        const { at, value } = JSON.parse(readFileSync(file(key), 'utf8'));
        if (Date.now() - at > maxAgeSec * 1000) return undefined;
        return value;
      } catch {
        return undefined;
      }
    },
    set(key, value) {
      try {
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const tmp = `${file(key)}.${process.pid}.tmp`;
        writeFileSync(tmp, JSON.stringify({ at: Date.now(), value }), { mode: 0o600 });
        renameSync(tmp, file(key));
      } catch {
        // A cache that cannot be written only makes the next run slower.
      }
    },
  };
}

/** An in-memory cache, for tests and one-off runs. */
export function memoryCache() {
  const m = new Map();
  return { get: (k) => m.get(k), set: (k, v) => m.set(k, v) };
}
