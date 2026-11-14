// SPDX-License-Identifier: AGPL-3.0-only
// A small tar reader, enough for container images (`docker save`, `podman save`, OCI image layouts) and the
// root filesystems of firmware builds (Yocto, Buildroot, Debian-based): ustar, GNU long names and POSIX pax
// headers. Archives are read as streams, gzip-compressed or not; only the files asked for are kept in memory.
import { open } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createGunzip } from 'node:zlib';
import * as zlib from 'node:zlib';

const BLOCK = 512;
export const GZIP = (b) => b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
export const ZSTD = (b) => b.length >= 4 && b[0] === 0x28 && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd;
const isTarHeader = (b) => b.length >= 262 && b.toString('latin1', 257, 262) === 'ustar';

/** Whether a file starts like a tar archive, a gzip stream or a zstd stream. */
export async function sniff(path) {
  const fh = await open(path, 'r');
  try {
    const b = Buffer.alloc(BLOCK);
    const { bytesRead } = await fh.read(b, 0, BLOCK, 0);
    const head = b.subarray(0, bytesRead);
    return GZIP(head) ? 'gzip' : ZSTD(head) ? 'zstd' : isTarHeader(head) ? 'tar' : null;
  } finally {
    await fh.close();
  }
}

const str = (b, start, len) => { const s = b.subarray(start, start + len); const z = s.indexOf(0); return s.toString('utf8', 0, z < 0 ? s.length : z); };
function num(b, start, len) {
  // Base-256 for very large values (GNU), octal otherwise.
  if (b[start] & 0x80) { let v = 0; for (let i = start + 1; i < start + len; i++) v = v * 256 + b[i]; return v; }
  const s = str(b, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}
function paxRecords(buf) {
  const out = {};
  let i = 0;
  while (i < buf.length) {
    const sp = buf.indexOf(0x20, i);
    if (sp < 0) break;
    const len = parseInt(buf.toString('utf8', i, sp), 10);
    if (!(len > 0)) break;
    const rec = buf.toString('utf8', sp + 1, i + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}
/** "./a/b", "/a/b", "a//b" → "a/b" (never above the root). */
export function normPath(p) {
  const out = [];
  for (const seg of String(p).split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') out.pop(); else out.push(seg);
  }
  return out.join('/');
}

/**
 * Reads a tar stream and calls `onEntry({ path, type, size, linkname })` for each entry; when it returns a
 * positive number (a size cap), the entry's content (if no larger) is passed to `onData(entry, buffer)`.
 * type: "file", "dir", "symlink", "hardlink" or "other".
 */
export async function readTar(stream, onEntry, onData) {
  let buf = Buffer.alloc(0);
  let state = { kind: 'header' };
  let pax = null; let globalPax = {}; let longName = null; let longLink = null;
  const take = (n) => { const out = buf.subarray(0, n); buf = buf.subarray(n); return out; };
  for await (const chunk of stream) {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (state.kind === 'header') {
        if (buf.length < BLOCK) break;
        const h = take(BLOCK);
        if (h.every((x) => x === 0)) continue;   // end-of-archive blocks
        const size = num(h, 124, 12);
        const flag = String.fromCharCode(h[156] || 0x30);
        let path = str(h, 0, 100);
        const prefix = h.toString('latin1', 257, 262) === 'ustar' ? str(h, 345, 155) : '';
        if (prefix) path = `${prefix}/${path}`;
        const padded = Math.ceil(size / BLOCK) * BLOCK;
        if (flag === 'x' || flag === 'g' || flag === 'L' || flag === 'K') { state = { kind: 'meta', flag, size, padded, data: [] }; continue; }
        const p = { ...globalPax, ...(pax ?? {}) };
        const entry = {
          path: normPath(p.path ?? longName ?? path),
          type: flag === '0' || flag === '\0' || flag === '7' ? 'file' : flag === '5' ? 'dir' : flag === '2' ? 'symlink' : flag === '1' ? 'hardlink' : 'other',
          size: p.size ? Number(p.size) : size,
          linkname: p.linkpath ?? longLink ?? str(h, 157, 100),
        };
        pax = null; longName = null; longLink = null;
        const cap = entry.type === 'file' ? onEntry(entry) : (onEntry(entry), 0);
        state = { kind: 'data', entry, left: entry.size, padded: Math.ceil(entry.size / BLOCK) * BLOCK, keep: cap > 0 && entry.size <= cap, data: [] };
        if (state.padded === 0) { if (state.keep) await onData(entry, Buffer.alloc(0)); state = { kind: 'header' }; }
        continue;
      }
      if (state.kind === 'meta') {
        if (buf.length < state.padded) break;
        const d = take(state.padded).subarray(0, state.size);
        if (state.flag === 'x') pax = paxRecords(d);
        else if (state.flag === 'g') globalPax = { ...globalPax, ...paxRecords(d) };
        else if (state.flag === 'L') longName = str(d, 0, d.length);
        else longLink = str(d, 0, d.length);
        state = { kind: 'header' };
        continue;
      }
      // data: consumed as it comes, so large files never sit in memory unless kept.
      if (!buf.length) break;
      const n = Math.min(buf.length, state.padded);
      const part = take(n);
      if (state.keep) {
        const useful = part.subarray(0, Math.max(0, Math.min(part.length, state.left)));
        if (useful.length) state.data.push(Buffer.from(useful));
      }
      state.left -= n; state.padded -= n;
      if (state.padded === 0) {
        if (state.keep) await onData(state.entry, Buffer.concat(state.data));
        state = { kind: 'header' };
      }
    }
  }
}

/** Opens part of a file (or all of it) as a stream, decompressed if it is gzip or zstd. */
export async function openStream(path, start = 0, end = undefined) {
  const fh = await open(path, 'r');
  const head = Buffer.alloc(4);
  try { await fh.read(head, 0, 4, start); } finally { await fh.close(); }
  const raw = createReadStream(path, { start, end });
  if (GZIP(head)) return raw.pipe(createGunzip());
  if (ZSTD(head)) {
    if (typeof zlib.createZstdDecompress !== 'function') throw new Error('this layer is compressed with zstd, which needs Node.js 22.15 or later');
    return raw.pipe(zlib.createZstdDecompress());
  }
  return raw;
}

/** Lists the entries of an uncompressed tar file with where their content lies (for archives of archives). */
export async function indexTar(path) {
  const fh = await open(path, 'r');
  const out = new Map();
  try {
    const { size: total } = await fh.stat();
    let pos = 0; let pax = null; let longName = null;
    const h = Buffer.alloc(BLOCK);
    while (pos + BLOCK <= total) {
      await fh.read(h, 0, BLOCK, pos);
      if (h.every((x) => x === 0)) { pos += BLOCK; continue; }
      const size = num(h, 124, 12);
      const flag = String.fromCharCode(h[156] || 0x30);
      const padded = Math.ceil(size / BLOCK) * BLOCK;
      if (flag === 'x' || flag === 'L') {
        const d = Buffer.alloc(size);
        await fh.read(d, 0, size, pos + BLOCK);
        if (flag === 'x') pax = paxRecords(d); else longName = str(d, 0, d.length);
        pos += BLOCK + padded;
        continue;
      }
      let name = str(h, 0, 100);
      const prefix = h.toString('latin1', 257, 262) === 'ustar' ? str(h, 345, 155) : '';
      if (prefix) name = `${prefix}/${name}`;
      name = normPath(pax?.path ?? longName ?? name);
      const realSize = pax?.size ? Number(pax.size) : size;
      if (flag === '0' || flag === '\0' || flag === '7') out.set(name, { start: pos + BLOCK, size: realSize });
      else if (flag === '2' || flag === '1') out.set(name, { link: normPath(flag === '2' && !str(h, 157, 100).startsWith('/') ? `${name.split('/').slice(0, -1).join('/')}/${str(h, 157, 100)}` : str(h, 157, 100)) });
      pax = null; longName = null;
      pos += BLOCK + Math.ceil(realSize / BLOCK) * BLOCK;
    }
  } finally {
    await fh.close();
  }
  return out;
}
