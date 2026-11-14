// SPDX-License-Identifier: AGPL-3.0-only
// A small tar reader, enough for container images (`docker save`, `podman save`, OCI image layouts) and the
// root filesystems of firmware builds (Yocto, Buildroot, Debian-based): ustar, GNU long names and POSIX pax
// headers. Archives are read as streams, gzip- or zstd-compressed or not; only the files asked for are kept in
// memory. Headers are checked (checksum, sizes) and a truncated archive is an error, never a shorter list.
import { open } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createGunzip } from 'node:zlib';
import * as zlib from 'node:zlib';

const BLOCK = 512;
const META_CAP = 1024 * 1024;   // a pax record set, a GNU long name or long link name
export const GZIP = (b) => b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
export const ZSTD = (b) => b.length >= 4 && b[0] === 0x28 && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd;

/** Whether a 512-byte block is a tar header: its checksum must match (signed or unsigned sum, as tar writers differ). */
export function validHeader(h) {
  if (h.length < BLOCK) return false;
  const stored = parseInt(h.toString('latin1', 148, 156).replace(/\0.*$/s, '').trim(), 8);
  if (!Number.isFinite(stored)) return false;
  let u = 0; let s = 0;
  for (let i = 0; i < BLOCK; i++) {
    const b = i >= 148 && i < 156 ? 0x20 : h[i];
    u += b; s += b > 127 ? b - 256 : b;
  }
  return stored === u || stored === s;
}

/** Whether a file starts like a tar archive, a gzip stream or a zstd stream. */
export async function sniff(path) {
  const fh = await open(path, 'r');
  try {
    const b = Buffer.alloc(BLOCK);
    const { bytesRead } = await fh.read(b, 0, BLOCK, 0);
    const head = b.subarray(0, bytesRead);
    return GZIP(head) ? 'gzip' : ZSTD(head) ? 'zstd' : validHeader(head) ? 'tar' : null;
  } finally {
    await fh.close();
  }
}

const str = (b, start, len) => { const s = b.subarray(start, start + len); const z = s.indexOf(0); return s.toString('utf8', 0, z < 0 ? s.length : z); };
/** A numeric field: octal, or base-256 (GNU) when the high bit is set. Throws on anything not a size. */
function num(b, start, len, what) {
  let v;
  if (b[start] & 0x80) {
    if (b[start] === 0xff) throw new Error(`corrupt tar header: negative ${what}`);
    v = b[start] & 0x7f;
    for (let i = start + 1; i < start + len; i++) v = v * 256 + b[i];
  } else {
    const s = str(b, start, len).trim();
    if (s && !/^[0-7]+$/.test(s)) throw new Error(`corrupt tar header: ${what} is not a number`);
    v = s ? parseInt(s, 8) : 0;
  }
  if (!Number.isSafeInteger(v) || v < 0) throw new Error(`corrupt tar header: ${what} out of range`);
  return v;
}
function paxRecords(buf) {
  const out = {};
  let i = 0;
  while (i < buf.length) {
    const sp = buf.indexOf(0x20, i);
    if (sp < 0) break;
    const len = Number(buf.toString('utf8', i, sp));
    if (!Number.isSafeInteger(len) || len <= sp - i + 1 || i + len > buf.length) throw new Error('corrupt pax header');
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

// Entry types that carry no data, whatever their size field says (as Go's archive/tar, which wrote most layers).
const HEADER_ONLY = new Set(['1', '2', '3', '4', '5', '6']);
const TYPES = { 0: 'file', '\0': 'file', 7: 'file', 1: 'hardlink', 2: 'symlink', 5: 'dir' };

/** Parses one header block, with the pending pax records and GNU long names. */
function parseHeader(h, meta) {
  if (!validHeader(h)) throw new Error('corrupt tar header (bad checksum)');
  const flag = String.fromCharCode(h[156]);
  let size = num(h, 124, 12, 'size');
  if (flag === 'x' || flag === 'g' || flag === 'L' || flag === 'K') {
    if (size > META_CAP) throw new Error(`tar ${flag === 'x' || flag === 'g' ? 'pax header' : 'long name'} too large (${size} bytes)`);
    return { meta: flag, size };
  }
  let path = str(h, 0, 100);
  // The ustar prefix field exists only in POSIX headers ("ustar\0" + "00"); GNU headers use those bytes for times.
  if (h.toString('latin1', 257, 263) === 'ustar\0' && h.toString('latin1', 263, 265) === '00') {
    const prefix = str(h, 345, 155);
    if (prefix) path = `${prefix}/${path}`;
  }
  const pax = meta.pax ?? {};
  if (pax.size !== undefined) {
    if (!/^\d+$/.test(pax.size) || !Number.isSafeInteger(Number(pax.size))) throw new Error('corrupt pax header: size');
    size = Number(pax.size);
  }
  if (HEADER_ONLY.has(flag)) size = 0;
  const entry = {
    path: normPath(pax.path ?? meta.longName ?? path),
    type: TYPES[flag] ?? 'other',
    size,
    linkname: pax.linkpath ?? meta.longLink ?? str(h, 157, 100),
  };
  meta.pax = null; meta.longName = null; meta.longLink = null;
  return { entry };
}
function applyMeta(meta, flag, d) {
  if (flag === 'x') meta.pax = paxRecords(d);
  else if (flag === 'L') meta.longName = str(d, 0, d.length);
  else if (flag === 'K') meta.longLink = str(d, 0, d.length);
  // 'g' (global pax records) is ignored, as by Go's archive/tar and the container runtimes.
}
const padded = (n) => Math.ceil(n / BLOCK) * BLOCK;

/**
 * Reads a tar stream and calls `onEntry({ path, type, size, linkname })` for each entry; when it returns a
 * positive number (a size cap), the entry's content (if no larger) is passed to `onData(entry, buffer)`.
 * type: "file", "dir", "symlink", "hardlink" or "other". Throws on a corrupt or truncated archive.
 */
export async function readTar(stream, onEntry, onData) {
  let buf = Buffer.alloc(0);
  let state = { kind: 'header' };
  const meta = { pax: null, longName: null, longLink: null };
  let ended = false;
  const take = (n) => { const out = buf.subarray(0, n); buf = buf.subarray(n); return out; };
  for await (const chunk of stream) {
    if (ended) continue;   // what follows the end-of-archive blocks is padding
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (state.kind === 'header') {
        if (buf.length < BLOCK) break;
        const h = take(BLOCK);
        if (h.every((x) => x === 0)) { ended = true; buf = Buffer.alloc(0); break; }
        const r = parseHeader(h, meta);
        if (r.meta) { state = { kind: 'meta', flag: r.meta, size: r.size, padded: padded(r.size) }; continue; }
        const entry = r.entry;
        const cap = Number(onEntry(entry)) || 0;
        state = { kind: 'data', entry, left: entry.size, padded: padded(entry.size), keep: entry.type === 'file' && cap > 0 && entry.size <= cap, data: [] };
        if (state.padded === 0) { if (state.keep) await onData(entry, Buffer.alloc(0)); state = { kind: 'header' }; }
        continue;
      }
      if (state.kind === 'meta') {
        if (buf.length < state.padded) break;
        applyMeta(meta, state.flag, take(state.padded).subarray(0, state.size));
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
  if (state.kind !== 'header' || (!ended && buf.length)) throw new Error('truncated tar archive');
}

/** Opens part of a file (or all of it) as a stream, decompressed if it is gzip or zstd. */
export async function openStream(path, start = 0, end = undefined) {
  const fh = await open(path, 'r');
  const head = Buffer.alloc(4);
  try { await fh.read(head, 0, 4, start); } finally { await fh.close(); }
  const raw = createReadStream(path, { start, end });
  if (GZIP(head)) return raw.pipe(createGunzip());
  if (ZSTD(head)) {
    if (typeof zlib.createZstdDecompress !== 'function') throw new Error('this archive is compressed with zstd, which needs Node.js 22.15 or later');
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
    let pos = 0;
    const meta = { pax: null, longName: null, longLink: null };
    const h = Buffer.alloc(BLOCK);
    while (pos + BLOCK <= total) {
      await fh.read(h, 0, BLOCK, pos);
      if (h.every((x) => x === 0)) break;
      const r = parseHeader(h, meta);
      const size = r.meta ? r.size : r.entry.size;
      if (pos + BLOCK + size > total) throw new Error('truncated tar archive');
      if (r.meta) {
        const d = Buffer.alloc(size);
        await fh.read(d, 0, size, pos + BLOCK);
        applyMeta(meta, r.meta, d);
      } else {
        const { entry } = r;
        if (entry.type === 'file') out.set(entry.path, { start: pos + BLOCK, size });
        else if (entry.type === 'symlink') out.set(entry.path, { link: normPath(entry.linkname.startsWith('/') ? entry.linkname : `${entry.path.split('/').slice(0, -1).join('/')}/${entry.linkname}`) });
        else if (entry.type === 'hardlink') out.set(entry.path, { link: normPath(entry.linkname) });
      }
      pos += BLOCK + padded(size);
    }
    if (pos + BLOCK > total && pos < total) throw new Error('truncated tar archive');
  } finally {
    await fh.close();
  }
  return out;
}
