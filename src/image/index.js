// SPDX-License-Identifier: AGPL-3.0-only
// The software inside a container image or a firmware root filesystem, read without running it:
//  - a container image saved with `docker save` or `podman save` (Docker archive or OCI layout, in one tar);
//  - a root filesystem archive (rootfs.tar, rootfs.tar.gz), as Yocto, Buildroot or debootstrap produce.
// Layers are applied in order, with their whiteouts, and only the package databases, os-release and the
// lock files and installed packages of language package managers are kept: never the rest of the image.
import { basename } from 'node:path';
import { sniff, indexTar, openStream, readTar, normPath } from './tar.js';
import { parseOsRelease, distroOf, parseDpkgStatus, parseApkInstalled, parseOpkgStatus, parsePythonMetadata, parseNodePackage } from './packages.js';
import { PARSERS, mergeComponents } from '../lockfiles/index.js';

const MB = 1024 * 1024;
const DB_CAP = 64 * MB;          // a package database
const SMALL_CAP = 2 * MB;        // os-release, METADATA, package.json
const LOCK_CAP = 20 * MB;        // a lock file, as for directories
const LOCK_NAMES = new Set(Object.keys(PARSERS).filter((k) => PARSERS[k]));
const RPM_DB = /^(var\/lib\/rpm\/(Packages|rpmdb\.sqlite)|usr\/lib\/sysimage\/rpm\/rpmdb\.sqlite)$/;

/** What a path is to us, and how much of it to keep (0: nothing). */
function wanted(path) {
  if (path === 'etc/os-release' || path === 'usr/lib/os-release') return { kind: 'os', cap: SMALL_CAP };
  if (path === 'var/lib/dpkg/status' || /^var\/lib\/dpkg\/status\.d\/[^/]+$/.test(path) && !/\.md5sums$/.test(path)) return { kind: 'dpkg', cap: DB_CAP };
  if (path === 'lib/apk/db/installed') return { kind: 'apk', cap: DB_CAP };
  if (path === 'var/lib/opkg/status' || path === 'usr/lib/opkg/status') return { kind: 'opkg', cap: DB_CAP };
  if (RPM_DB.test(path)) return { kind: 'rpm', cap: 0 };
  if (/(^|\/)(site|dist)-packages\/[^/]+\.(dist-info\/METADATA|egg-info\/PKG-INFO)$/.test(path)) return { kind: 'python', cap: SMALL_CAP };
  if (/(^|\/)node_modules\/(@[^/]+\/)?[^/@.][^/]*\/package\.json$/.test(path)) return { kind: 'node', cap: SMALL_CAP };
  const base = basename(path);
  if (LOCK_NAMES.has(base) && !/(^|\/)(node_modules|vendor|proc|sys)\//.test(path)) return { kind: 'lock', cap: LOCK_CAP };
  return null;
}

/** The files kept so far, as the layers are applied one after the other. */
class Layers {
  constructor() { this.files = new Map(); this.links = new Map(); this.rpm = new Set(); }
  remove(path) {
    for (const m of [this.files, this.links]) for (const k of [...m.keys()]) if (k === path || k.startsWith(`${path}/`)) m.delete(k);
    for (const k of [...this.rpm]) if (k === path || k.startsWith(`${path}/`)) this.rpm.delete(k);
  }
  async apply(stream) {
    await readTar(stream, (e) => {
      const name = basename(e.path);
      const dir = e.path.slice(0, -name.length).replace(/\/$/, '');
      // Whiteouts: a file deleted by this layer, or a directory emptied of what earlier layers put in it.
      if (name === '.wh..wh..opq') { this.remove(dir); return 0; }
      if (name.startsWith('.wh.')) { this.remove(dir ? `${dir}/${name.slice(4)}` : name.slice(4)); return 0; }
      if (e.type === 'dir') return 0;
      const w = wanted(e.path);
      this.files.delete(e.path); this.links.delete(e.path);
      if (!w) return 0;
      if (w.kind === 'rpm') { this.rpm.add(e.path); return 0; }
      if (e.type === 'symlink' || e.type === 'hardlink') {
        const target = e.type === 'symlink' && !e.linkname.startsWith('/') ? normPath(`${dir}/${e.linkname}`) : normPath(e.linkname);
        this.links.set(e.path, target);
        return 0;
      }
      return e.type === 'file' ? w.cap : 0;
    }, (e, data) => { this.files.set(e.path, data); });
  }
  /** A kept file, following symbolic links among kept files (os-release is often one). */
  read(path, depth = 0) {
    if (this.files.has(path)) return this.files.get(path);
    const to = this.links.get(path);
    return to && depth < 8 ? this.read(to, depth + 1) : null;
  }
}

async function parseAll(layers) {
  const notices = [];
  const errors = [];
  const osText = layers.read('etc/os-release') ?? layers.read('usr/lib/os-release');
  const os = osText ? parseOsRelease(osText.toString('utf8')) : null;
  const dist = distroOf(os);
  const lists = [];
  const paths = [...new Set([...layers.files.keys(), ...layers.links.keys()])].sort();
  for (const path of paths) {
    const w = wanted(path);
    if (!w || w.kind === 'os') continue;
    const data = layers.read(path);
    if (!data) continue;
    const text = data.toString('utf8');
    try {
      if (w.kind === 'dpkg') lists.push(parseDpkgStatus(text, path, dist));
      else if (w.kind === 'apk') lists.push(parseApkInstalled(text, path, dist));
      else if (w.kind === 'opkg') lists.push(parseOpkgStatus(text, path, dist));
      else if (w.kind === 'python') lists.push(parsePythonMetadata(text, path));
      else if (w.kind === 'node') lists.push(parseNodePackage(text, path));
      else if (w.kind === 'lock') {
        const comps = await PARSERS[basename(path)](text);
        lists.push(comps.map((c) => ({ ...c, sources: [path] })));
      }
    } catch (e) {
      errors.push({ file: path, error: `${path}: cannot be read (${e.message})` });
    }
  }
  if (layers.rpm.size) notices.push({ file: [...layers.rpm][0], text: `${[...layers.rpm][0]}: RPM package databases are not read yet; the packages it lists are not in the SBOM.` });
  if (lists.some((l) => l.some((c) => c.type === 'opkg'))) notices.push({ file: 'opkg', text: 'opkg packages are listed in the SBOM, but no public advisory database covers them: they are not looked up.' });
  if (!os) notices.push({ file: 'os-release', text: 'No os-release file: the operating system and its release are unknown, so its packages cannot be looked up.' });
  const components = mergeComponents(lists);
  return { components, os, files: paths.filter((p) => wanted(p)?.kind !== 'os'), errors, notices };
}

async function readJsonEntry(path, idx, name) {
  let e = idx.get(name);
  for (let i = 0; e?.link && i < 8; i++) e = idx.get(e.link);
  if (!e || e.size > SMALL_CAP) throw new Error(`${name}: missing or too large`);
  const chunks = [];
  for await (const c of await openStream(path, e.start, e.start + e.size - 1)) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
const blobPath = (digest) => `blobs/${String(digest).replace(':', '/')}`;

/** The layer files of the image in an archive, in order, and the image's name if it says one. */
async function imageLayers(path, idx) {
  if (idx.has('manifest.json')) {
    const m = await readJsonEntry(path, idx, 'manifest.json');
    if (!Array.isArray(m) || !m.length || !Array.isArray(m[0].Layers)) throw new Error('manifest.json: no image in this archive');
    return { layers: m[0].Layers.map(normPath), name: m[0].RepoTags?.[0] ?? '', more: m.length > 1 };
  }
  // OCI layout: index.json → (an index for several platforms →) the image manifest → its layers.
  let desc = (await readJsonEntry(path, idx, 'index.json')).manifests?.[0];
  const name = desc?.annotations?.['org.opencontainers.image.ref.name'] ?? '';
  for (let i = 0; i < 4 && desc; i++) {
    const doc = await readJsonEntry(path, idx, blobPath(desc.digest));
    if (Array.isArray(doc.layers)) return { layers: doc.layers.map((l) => blobPath(l.digest)), name, more: false };
    const list = doc.manifests ?? [];
    desc = list.find((x) => x.platform?.os === 'linux' && x.platform?.architecture === 'amd64') ?? list.find((x) => x.platform?.os === 'linux') ?? list[0];
  }
  throw new Error('index.json: no image manifest found');
}

/**
 * Reads a container image archive or a root filesystem archive. Returns { components, os, name, files,
 * errors, notices }, components shaped like those read from lock files (sources: the paths inside).
 */
export async function readImage(path) {
  const kind = await sniff(path);
  if (!kind) throw new Error(`${basename(path)} is neither a tar archive nor a compressed one`);
  const layers = new Layers();
  let name = '';
  const notices = [];
  const idx = kind === 'tar' ? await indexTar(path) : null;
  if (idx && (idx.has('manifest.json') || (idx.has('index.json') && idx.has('oci-layout')))) {
    const img = await imageLayers(path, idx);
    name = img.name;
    if (img.more) notices.push({ file: 'manifest.json', text: 'This archive holds several images: only the first one is read.' });
    for (const l of img.layers) {
      let e = idx.get(l);
      for (let i = 0; e?.link && i < 8; i++) e = idx.get(e.link);
      if (!e?.size && e?.size !== 0) throw new Error(`${l}: layer missing from the archive`);
      if (e.size === 0) continue;
      await layers.apply(await openStream(path, e.start, e.start + e.size - 1));
    }
  } else {
    await layers.apply(await openStream(path));
  }
  const out = await parseAll(layers);
  return { ...out, name, notices: [...notices, ...out.notices] };
}

/** Whether a file looks like an archive readImage can read (tar, gzip or zstd). */
export async function isArchive(path) {
  return Boolean(await sniff(path).catch(() => null));
}
