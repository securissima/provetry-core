// SPDX-License-Identifier: AGPL-3.0-only
// The RPM package database in its SQLite form (rpmdb.sqlite: Red Hat Enterprise Linux 9 and later, AlmaLinux,
// Rocky Linux, Fedora, CentOS Stream), read from memory without running anything: just enough of the SQLite
// file format to walk one table (https://www.sqlite.org/fileformat2.html), and of the RPM header format to
// take a package's name, version, release, epoch, architecture and source package.
// The file comes from an image we do not trust: every offset is checked, and the walk is bounded.
import { makeOsPurl } from '../purl.js';

const MAX_ROWS = 200_000;
const MAX_PAYLOAD = 32 * 1024 * 1024;   // one row
const MAX_COPIED = 256 * 1024 * 1024;   // all the rows that spill over several pages, together

class Reader {
  constructor(buf) {
    if (buf.length < 100 || buf.toString('latin1', 0, 16) !== 'SQLite format 3\0') throw new Error('not an SQLite database');
    this.buf = buf;
    const ps = buf.readUInt16BE(16);
    this.pageSize = ps === 1 ? 65536 : ps;
    if (this.pageSize < 512 || (this.pageSize & (this.pageSize - 1)) !== 0) throw new Error('bad page size');
    this.usable = this.pageSize - buf[20];
    if (this.usable < 480) throw new Error('bad reserved size');
    this.pages = Math.floor(buf.length / this.pageSize);
    this.seen = new Set();   // a page belongs to one place only: a second visit is damage, or an attempt to make us loop
    this.rows = 0;
    this.read = 0;
    this.copied = 0;
  }
  page(n) {
    if (!Number.isInteger(n) || n < 1 || n > this.pages) throw new Error(`page ${n} is outside the file`);
    if (this.seen.has(n)) throw new Error(`page ${n} is used twice`);
    this.seen.add(n);
    return (n - 1) * this.pageSize;
  }
  varint(pos, end) {
    let v = 0n;
    for (let i = 0; i < 9; i++) {
      if (pos >= end) throw new Error('truncated varint');
      const b = this.buf[pos++];
      if (i === 8) return [(v << 8n) | BigInt(b), pos];
      v = (v << 7n) | BigInt(b & 0x7f);
      if (!(b & 0x80)) break;
    }
    return [v, pos];
  }
  /** Every row of the table rooted at `root`: calls row(rowid, payload). */
  walk(root, row, depth = 0) {
    if (depth > 20) throw new Error('table too deep');
    const start = this.page(root);
    const end = start + this.pageSize;
    const h = start + (root === 1 ? 100 : 0);
    const type = this.buf[h];
    if (type !== 13 && type !== 5) throw new Error('not a table page');
    const cells = this.buf.readUInt16BE(h + 3);
    const ptrs = h + (type === 5 ? 12 : 8);
    if (ptrs + 2 * cells > end) throw new Error('cell pointers outside the page');
    const cellsSeen = new Set();
    for (let i = 0; i < cells; i++) {
      const cell = start + this.buf.readUInt16BE(ptrs + 2 * i);
      if (cell < h || cell + 4 > end) throw new Error('cell outside the page');
      if (cellsSeen.has(cell)) throw new Error('cell used twice');
      cellsSeen.add(cell);
      if (type === 5) { this.walk(this.buf.readUInt32BE(cell), row, depth + 1); continue; }
      let [size, pos] = this.varint(cell, end);
      let rowid;
      [rowid, pos] = this.varint(pos, end);
      const total = Number(size);
      if (total > MAX_PAYLOAD) throw new Error('row too large');
      // Rows cannot hold more than the file does.
      if (++this.rows > MAX_ROWS || (this.read += total) > this.buf.length) throw new Error('more rows than the file can hold');
      // How much of the payload is on this page; the rest is a chain of overflow pages.
      const U = this.usable, X = U - 35, M = Math.floor(((U - 12) * 32) / 255) - 23;
      let local = total;
      if (total > X) { const K = M + ((total - M) % (U - 4)); local = K <= X ? K : M; }
      if (pos + local + (local < total ? 4 : 0) > end) throw new Error('payload outside the page');
      const parts = [this.buf.subarray(pos, pos + local)];
      let left = total - local;
      if (left > 0 && (this.copied += total) > MAX_COPIED) throw new Error('database too large');
      let next = left > 0 ? this.buf.readUInt32BE(pos + local) : 0;
      while (left > 0) {
        const o = this.page(next);
        const take = Math.min(left, U - 4);
        parts.push(this.buf.subarray(o + 4, o + 4 + take));
        left -= take;
        next = this.buf.readUInt32BE(o);
      }
      row(rowid, parts.length === 1 ? parts[0] : Buffer.concat(parts));
    }
    if (type === 5) this.walk(this.buf.readUInt32BE(h + 8), row, depth + 1);
  }
  /** The columns of a record: null, bigint, Buffer (blob) or string. Floats are not needed: null. */
  record(payload) {
    const view = new Reader.View(payload);
    let [hsize, pos] = view.varint(0);
    const hend = Number(hsize);
    if (hend > payload.length) throw new Error('record header outside the row');
    const types = [];
    while (pos < hend) { let t; [t, pos] = view.varint(pos); types.push(Number(t)); }
    let at = hend;
    return types.map((t) => {
      const len = t >= 12 ? (t - 12 - (t & 1)) / 2 : [0, 1, 2, 3, 4, 6, 8, 8, 0, 0][t] ?? 0;
      if (at + len > payload.length) throw new Error('column outside the row');
      const raw = payload.subarray(at, at + len);
      at += len;
      if (t === 0 || t === 7 || t === 10 || t === 11) return null;
      if (t === 8) return 0n;
      if (t === 9) return 1n;
      if (t < 7) return len ? BigInt.asIntN(len * 8, BigInt(`0x${raw.toString('hex')}`)) : 0n;
      return t & 1 ? raw.toString('utf8') : raw;
    });
  }
}
Reader.View = class {
  constructor(buf) { this.buf = buf; }
  varint(pos) {
    let v = 0n;
    for (let i = 0; i < 9; i++) {
      if (pos >= this.buf.length) throw new Error('truncated varint');
      const b = this.buf[pos++];
      if (i === 8) return [(v << 8n) | BigInt(b), pos];
      v = (v << 7n) | BigInt(b & 0x7f);
      if (!(b & 0x80)) break;
    }
    return [v, pos];
  }
};

/** The header blobs of the Packages table of an rpmdb.sqlite file, and how many rows had none. */
export function rpmHeaderBlobs(buf) {
  const db = new Reader(buf);
  let root = 0;
  db.walk(1, (_id, payload) => {
    const [type, name, , rootpage] = db.record(payload);
    if (type === 'table' && name === 'Packages' && typeof rootpage === 'bigint') root = Number(rootpage);
  });
  if (!root) throw new Error('no Packages table');
  const out = [];
  let skipped = 0;
  db.walk(root, (_id, payload) => {
    const blob = db.record(payload).find((c) => Buffer.isBuffer(c));
    if (blob) out.push(blob); else skipped++;
  });
  return { blobs: out, skipped };
}

const TAG = { name: 1000, version: 1001, release: 1002, epoch: 1003, arch: 1022, sourcerpm: 1044 };

/** { name, version, release, epoch, arch, sourcerpm } from an RPM header blob (as stored in the database: no lead, no magic). */
export function parseRpmHeader(blob) {
  if (blob.length < 8) throw new Error('truncated header');
  const il = blob.readUInt32BE(0);
  const dl = blob.readUInt32BE(4);
  const data = 8 + 16 * il;
  if (il > 65536 || data + dl > blob.length) throw new Error('header outside the row');
  const out = {};
  const want = new Map(Object.entries(TAG).map(([k, v]) => [v, k]));
  for (let i = 0; i < il; i++) {
    const e = 8 + 16 * i;
    const key = want.get(blob.readUInt32BE(e));
    if (!key) continue;
    const type = blob.readUInt32BE(e + 4);
    const at = data + blob.readUInt32BE(e + 8);
    if (at >= data + dl) throw new Error('value outside the header');
    if (type === 4) {            // INT32
      if (at + 4 > data + dl) throw new Error('value outside the header');
      out[key] = String(blob.readUInt32BE(at));
    } else if (type === 6 || type === 9) {   // STRING, I18NSTRING
      const nul = blob.indexOf(0, at);
      if (nul < 0 || nul >= data + dl || nul - at > 4096) throw new Error('unterminated string');
      out[key] = blob.toString('utf8', at, nul);
    }
  }
  return out;
}

/** The purl namespace and distro qualifier of an RPM-based release, as SBOM tools spell them ("redhat", "rhel-9.3"). */
export function rpmDistro(os) {
  if (!os?.id) return { namespace: 'rpm', distro: '' };
  return { namespace: os.id === 'rhel' ? 'redhat' : os.id, distro: os.versionId ? `${os.id}-${os.versionId}` : '' };
}

const SAFE = /^[\w.+~^-]+$/;

/**
 * The installed packages of an rpmdb.sqlite file: { components, skipped }. gpg-pubkey entries are keys, not
 * packages; `skipped` counts the rows that could not be made a component (no header, no name, an odd name).
 */
export function parseRpmSqlite(buf, source, os) {
  const { namespace, distro } = rpmDistro(os);
  const { blobs, skipped: empty } = rpmHeaderBlobs(buf);
  const out = [];
  let skipped = empty;
  for (const blob of blobs) {
    const h = parseRpmHeader(blob);
    if (h.name === 'gpg-pubkey') continue;
    if (!h.name || !h.version || !h.release || ![h.name, h.version, h.release].every((s) => SAFE.test(s))) { skipped++; continue; }
    const version = `${h.version}-${h.release}`;
    const epoch = h.epoch && h.epoch !== '0' ? h.epoch : '';
    out.push({
      type: 'rpm', name: h.name, version: epoch ? `${epoch}:${version}` : version, scope: 'required', sources: [source],
      purl: makeOsPurl('rpm', namespace, h.name, version, { arch: h.arch, distro, epoch, upstream: h.sourcerpm && SAFE.test(h.sourcerpm) ? h.sourcerpm : '' }),
    });
  }
  return { components: out, skipped };
}
