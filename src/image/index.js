// SPDX-License-Identifier: AGPL-3.0-only
// The software inside a container image or a firmware root filesystem, read without running it:
//  - a container image saved with `docker save` or `podman save` (Docker archive or OCI layout, in one tar);
//  - a root filesystem archive (rootfs.tar, rootfs.tar.gz, rootfs.tar.zst), as Yocto, Buildroot or debootstrap produce.
// Layers are applied in order, with their whiteouts, and only the package databases, os-release and the
// lock files and installed packages of language package managers are kept: never the rest of the image.
// What cannot be read (a file too large, an RPM database, a release no advisory database covers) is said,
// and marked as making the result incomplete: never a silently shorter list.
import { basename, join } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { tmpdir } from 'node:os';
import { sniff, indexTar, openStream, readTar, normPath } from './tar.js';
import { parseOsRelease, distroOf, parseDpkgStatus, parseApkInstalled, parseOpkgStatus, parsePythonMetadata, parseNodePackage } from './packages.js';
import { PARSERS, mergeComponents } from '../lockfiles/index.js';

const MB = 1024 * 1024;
const DB_CAP = 64 * MB;          // a package database
const SMALL_CAP = 2 * MB;        // os-release, METADATA, package.json
const LOCK_CAP = 20 * MB;        // a lock file, as for directories
const TOTAL_BYTES = 512 * MB;    // all the files kept, across layers
const TOTAL_FILES = 200_000;     // all the paths kept, across layers
const LOCK_NAMES = new Set(Object.keys(PARSERS).filter((k) => PARSERS[k]));
const RPM_DB = /^(var\/lib\/rpm\/(Packages|rpmdb\.sqlite)|usr\/lib\/sysimage\/rpm\/rpmdb\.sqlite)$/;
// Lock files that describe no installed software: caches, documentation, test fixtures, examples.
const NOT_INSTALLED = /(^|\/)(node_modules|vendor|\.cache|\.npm|\.yarn|\.pnpm-store|\.cargo|\.git|tests?|testdata|fixtures|__tests__|__fixtures__|examples?|samples?)\//;
const SYSTEM_DIRS = /^(proc|sys|dev|tmp|var\/tmp|var\/cache|usr\/share|root\/go\/pkg|go\/pkg)\//;
// Python packages that Debian and Ubuntu install themselves: already listed through dpkg.
const DEBIAN_PYTHON = /^usr\/lib\/python3[^/]*\/dist-packages\//;

export const DEFAULT_PLATFORM = 'linux/amd64';

/** What a path is to us, and how much of it to keep (0: nothing). */
function wanted(path) {
  if (path === 'etc/os-release' || path === 'usr/lib/os-release') return { kind: 'os', cap: SMALL_CAP };
  if (path === 'var/lib/dpkg/status' || /^var\/lib\/dpkg\/status\.d\/[^/]+$/.test(path) && !/\.md5sums$/.test(path)) return { kind: 'dpkg', cap: DB_CAP };
  if (path === 'lib/apk/db/installed') return { kind: 'apk', cap: DB_CAP };
  if (path === 'var/lib/opkg/status' || path === 'usr/lib/opkg/status') return { kind: 'opkg', cap: DB_CAP };
  if (RPM_DB.test(path)) return { kind: 'rpm', cap: 0 };
  if (SYSTEM_DIRS.test(path)) return null;
  // dist-info/METADATA, egg-info/PKG-INFO, or an egg-info that is a single file (older setuptools).
  if (/(^|\/)(site|dist)-packages\/[^/]+\.(dist-info\/METADATA|egg-info\/PKG-INFO|egg-info)$/.test(path)) return { kind: 'python', cap: SMALL_CAP };
  if (/(^|\/)node_modules\/(@[^/]+\/)?[^/@.][^/]*\/package\.json$/.test(path)) return { kind: 'node', cap: SMALL_CAP };
  const base = basename(path);
  if (LOCK_NAMES.has(base) && !NOT_INSTALLED.test(path)) return { kind: 'lock', cap: LOCK_CAP };
  return null;
}

/** The files kept so far, as the layers are applied one after the other. */
class Layers {
  constructor() {
    this.files = new Map();     // path → content
    this.links = new Map();     // path → target path
    this.rpm = new Set();
    this.tooLarge = new Map();  // path → size: wanted, but over its cap
    this.dirs = new Map();      // directory → how many kept paths lie under it (to find them without a full scan)
    this.bytes = 0;
  }
  has(path) { return this.files.has(path) || this.links.has(path) || this.rpm.has(path) || this.tooLarge.has(path); }
  count() { return this.files.size + this.links.size + this.rpm.size + this.tooLarge.size; }
  track(path, delta) {
    for (let i = path.lastIndexOf('/'); i > 0; i = path.lastIndexOf('/', i - 1)) {
      const d = path.slice(0, i);
      const n = (this.dirs.get(d) ?? 0) + delta;
      if (n > 0) this.dirs.set(d, n); else this.dirs.delete(d);
    }
  }
  drop(path) {
    if (!this.has(path)) return;
    if (this.files.has(path)) this.bytes -= this.files.get(path).length;
    this.files.delete(path); this.links.delete(path); this.rpm.delete(path); this.tooLarge.delete(path);
    this.track(path, -1);
  }
  /** Removes a path and, if it is a directory holding kept paths, all of them. */
  remove(path, keepItself = false) {
    if (!keepItself) this.drop(path);
    if (!this.dirs.has(path)) return;
    const prefix = `${path}/`;
    for (const m of [this.files, this.links, this.rpm, this.tooLarge]) for (const k of [...m.keys()]) if (k.startsWith(prefix)) this.drop(k);
  }
  set(path, what) {
    this.drop(path);
    if (what.data) { this.files.set(path, what.data); this.bytes += what.data.length; }
    else if (what.link !== undefined) this.links.set(path, what.link);
    else if (what.rpm) this.rpm.add(path);
    else if (what.tooLarge !== undefined) this.tooLarge.set(path, what.tooLarge);
    this.track(path, 1);
    if (this.bytes > TOTAL_BYTES) throw new Error(`more than ${TOTAL_BYTES / MB} MB of package databases and lock files: not read`);
    if (this.count() > TOTAL_FILES) throw new Error(`more than ${TOTAL_FILES} package files: not read`);
  }
  /**
   * Applies one layer. Its whiteouts apply to the layers below only (OCI image spec), so the layer is read
   * whole first: then what it deletes is deleted, and what it adds is added. A file or link that replaces a
   * directory hides everything the lower layers had under it.
   */
  async apply(stream) {
    const whiteouts = []; const opaque = []; const replaced = []; const adds = new Map();
    let staged = 0;
    await readTar(stream, (e) => {
      const name = basename(e.path);
      const dir = e.path.slice(0, -name.length).replace(/\/$/, '');
      if (name === '.wh..wh..opq') { opaque.push(dir); return 0; }
      if (name.startsWith('.wh.')) { whiteouts.push(dir ? `${dir}/${name.slice(4)}` : name.slice(4)); return 0; }
      if (e.type === 'dir') return 0;
      if (this.dirs.has(e.path)) replaced.push(e.path);
      adds.delete(e.path);
      const w = wanted(e.path);
      if (!w) { if (this.has(e.path)) replaced.push(e.path); return 0; }
      if (w.kind === 'rpm') { adds.set(e.path, { rpm: true }); return 0; }
      if (e.type === 'symlink' || e.type === 'hardlink') {
        // A symbolic link is relative to its directory; a hard link names a path from the archive's root.
        adds.set(e.path, { link: e.type === 'symlink' && !e.linkname.startsWith('/') ? normPath(`${dir}/${e.linkname}`) : normPath(e.linkname) });
        return 0;
      }
      if (e.type !== 'file') { replaced.push(e.path); return 0; }
      if (e.size > w.cap) { adds.set(e.path, { tooLarge: e.size }); return 0; }
      if (adds.size > TOTAL_FILES) throw new Error(`more than ${TOTAL_FILES} package files in one layer: not read`);
      return w.cap;
    }, (e, data) => {
      staged += data.length;
      if (staged > TOTAL_BYTES) throw new Error(`more than ${TOTAL_BYTES / MB} MB of package databases and lock files in one layer: not read`);
      adds.set(e.path, { data });
    });
    for (const d of opaque) this.remove(d, true);
    for (const p of whiteouts) this.remove(p);
    for (const p of replaced) this.remove(p);
    for (const [p, what] of adds) { this.remove(p); this.set(p, what); }
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
  const hasDpkg = paths.some((p) => wanted(p)?.kind === 'dpkg');
  for (const path of paths) {
    const w = wanted(path);
    if (!w || w.kind === 'os') continue;
    if (w.kind === 'python' && hasDpkg && DEBIAN_PYTHON.test(path)) continue;
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
  for (const [path, size] of [...layers.tooLarge].sort()) errors.push({ file: path, error: `${path}: too large to read (${Math.round(size / MB)} MB)` });
  if (layers.rpm.size) notices.push({ file: [...layers.rpm][0], incomplete: true, text: `${[...layers.rpm][0]}: RPM package databases are not read yet; the packages it lists are not in the SBOM.` });
  const osPackages = lists.some((l) => l.some((c) => c.type === 'deb' || c.type === 'apk'));
  if (lists.some((l) => l.some((c) => c.type === 'opkg'))) notices.push({ file: 'opkg', incomplete: true, text: 'opkg packages are listed in the SBOM, but no public advisory database covers them: they are not looked up.' });
  if (osPackages && !os) notices.push({ file: 'os-release', incomplete: true, text: 'No os-release file: the operating system and its release are unknown, so its packages cannot be looked up.' });
  else if (osPackages && dist && !dist.lookup) notices.push({ file: 'os-release', incomplete: true, text: `${dist.why}.` });
  else if (osPackages && dist?.derived) notices.push({ file: 'os-release', text: `${dist.derived}.` });
  const components = mergeComponents(lists);
  return { components, os, files: paths.filter((p) => wanted(p)?.kind !== 'os'), errors, notices };
}

async function readJsonEntry(path, idx, name) {
  let e = idx.get(name);
  for (let i = 0; e?.link && i < 8; i++) e = idx.get(e.link);
  if (!e || e.link || e.size > SMALL_CAP) throw new Error(`${name}: missing or too large`);
  const chunks = [];
  if (e.size) for await (const c of await openStream(path, e.start, e.start + e.size - 1)) chunks.push(c);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
const blobPath = (digest) => `blobs/${String(digest).replace(':', '/')}`;

const INDEX_TYPES = new Set(['application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json']);
const MANIFEST_TYPES = new Set(['application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json']);
const FOREIGN = /(foreign|nondistributable)/;
const isLayerType = (t) => !t || /(\.layer\.v1\.tar|\.rootfs\.diff\.tar|\.image\.rootfs)/.test(t);
const platformOf = (d) => (d.platform ? [d.platform.os, d.platform.architecture, d.platform.variant].filter(Boolean).join('/') : '');

/** A Docker archive's manifest.json, if it really is one (a root filesystem may carry a file of that name). */
function dockerManifest(m, idx) {
  if (!Array.isArray(m) || !m.length) return null;
  if (!m.every((x) => x && typeof x.Config === 'string' && Array.isArray(x.Layers) && x.Layers.every((l) => typeof l === 'string'))) return null;
  return m[0].Layers.every((l) => idx.has(normPath(l))) ? m : null;
}

/** "registry:5000/acme/gateway:4.2.0" → { name: "registry:5000/acme/gateway", version: "4.2.0" } (a digest is not a version). */
function splitRef(ref) {
  const r = String(ref ?? '').split('@')[0];
  const slash = r.lastIndexOf('/');
  const colon = r.lastIndexOf(':');
  return colon > slash ? { name: r.slice(0, colon), version: r.slice(colon + 1) } : { name: r, version: '' };
}

/** The layers of the image in an archive, in order, its name and version if it says them, and notices. */
async function imageLayers(path, idx, platform) {
  const notices = [];
  if (idx.has('manifest.json')) {
    const m = dockerManifest(await readJsonEntry(path, idx, 'manifest.json').catch(() => null), idx);
    if (m) {
      if (m.length > 1) notices.push({ file: 'manifest.json', incomplete: true, text: `This archive holds ${m.length} images: only the first one (${m[0].RepoTags?.[0] ?? 'untagged'}) is read. Save one image per archive.` });
      return { layers: m[0].Layers.map((l) => ({ path: normPath(l) })), ...splitRef(m[0].RepoTags?.[0]), notices };
    }
    if (!idx.has('index.json')) return null;
  }
  if (!idx.has('index.json') || !idx.has('oci-layout')) return null;
  // OCI layout: index.json → (an index for several platforms →) the image manifest → its layers.
  const top = (await readJsonEntry(path, idx, 'index.json')).manifests ?? [];
  const images = top.filter((d) => !d.mediaType || INDEX_TYPES.has(d.mediaType) || MANIFEST_TYPES.has(d.mediaType));
  if (!images.length) throw new Error('index.json: no image in this archive');
  if (images.length > 1) notices.push({ file: 'index.json', incomplete: true, text: `This archive holds ${images.length} images: only the first one is read. Save one image per archive.` });
  let desc = images[0];
  const ann = desc.annotations ?? {};
  // containerd writes the full reference; ref.name is often only the tag.
  const full = ann['io.containerd.image.name'];
  const refName = ann['org.opencontainers.image.ref.name'] ?? '';
  const id = full ? splitRef(full) : /[/:]/.test(refName) ? splitRef(refName) : { name: '', version: refName };
  for (let i = 0; i < 4 && desc; i++) {
    const doc = await readJsonEntry(path, idx, blobPath(desc.digest));
    if (Array.isArray(doc.layers)) {
      const layers = [];
      for (const l of doc.layers) {
        if (FOREIGN.test(l.mediaType ?? '') && !idx.has(blobPath(l.digest))) {
          notices.push({ file: blobPath(l.digest), incomplete: true, text: `A layer of this image is not in the archive (${l.mediaType}, often a Windows base layer): what it holds is not in the SBOM.` });
          continue;
        }
        if (!isLayerType(l.mediaType)) throw new Error(`not a container image (layer type ${l.mediaType})`);
        layers.push({ path: blobPath(l.digest) });
      }
      return { layers, ...id, notices };
    }
    // An index: the images for each platform. Attestations and other artifacts are not images.
    // Only the platforms whose images are in the archive: `docker save` keeps the index of every platform,
    // but only the blobs of those pulled.
    const list = (doc.manifests ?? []).filter((x) => (!x.mediaType || MANIFEST_TYPES.has(x.mediaType) || INDEX_TYPES.has(x.mediaType)) && x.platform?.os !== 'unknown' && !x.annotations?.['vnd.docker.reference.type'] && idx.has(blobPath(x.digest)));
    const plats = [...new Set(list.map(platformOf).filter(Boolean))];
    const want = platform ?? DEFAULT_PLATFORM;
    const pick = list.find((x) => platformOf(x) === want) ?? list.find((x) => `${x.platform?.os}/${x.platform?.architecture}` === want);
    if (!pick) {
      if (platform || list.length !== 1) throw new Error(`no image for ${want} in this archive (it has: ${plats.join(', ') || 'none'}); pass --platform`);
      desc = list[0];
    } else desc = pick;
    if (list.length > 1) notices.push({ file: 'index.json', text: `This image is published for ${plats.length} platforms (${plats.join(', ')}): the ${platformOf(desc) || want} one is read${platform ? '' : ', pass --platform for another'}.` });
  }
  throw new Error('index.json: no image manifest found');
}

/**
 * Reads a container image archive or a root filesystem archive, compressed or not. Returns { components, os,
 * name, version, files, errors, notices }, components shaped like those read from lock files (sources: the
 * paths inside). Notices marked `incomplete` say what the SBOM is missing.
 * @param {{ platform?: string }} [opts] the platform to read from a multi-platform image ("linux/arm64")
 */
export async function readImage(path, opts = {}) {
  const kind = await sniff(path);
  if (!kind) throw new Error(`${basename(path)} is neither a tar archive nor a compressed one`);
  // A compressed archive could be a saved image as well as a root filesystem: decompressed first, to look.
  let tmp = null;
  let tarPath = path;
  try {
    if (kind !== 'tar') {
      tmp = await mkdtemp(join(tmpdir(), 'provetry-'));
      tarPath = join(tmp, 'archive.tar');
      await pipeline(await openStream(path), createWriteStream(tarPath));
      if (await sniff(tarPath) !== 'tar') throw new Error(`${basename(path)} is compressed, but not a tar archive`);
    }
    const idx = await indexTar(tarPath);
    const layers = new Layers();
    const img = await imageLayers(tarPath, idx, opts.platform);
    if (opts.platform && !img) throw new Error('--platform applies to container images, not to a root filesystem');
    if (img) {
      for (const l of img.layers) {
        let e = idx.get(l.path);
        for (let i = 0; e?.link && i < 8; i++) e = idx.get(e.link);
        if (!e || e.link) throw new Error(`${l.path}: layer missing from the archive`);
        if (e.size === 0) continue;
        await layers.apply(await openStream(tarPath, e.start, e.start + e.size - 1));
      }
    } else {
      await layers.apply(await openStream(tarPath));
    }
    const out = await parseAll(layers);
    return { ...out, name: img?.name ?? '', version: img?.version ?? '', notices: [...(img?.notices ?? []), ...out.notices] };
  } finally {
    if (tmp) await rm(tmp, { recursive: true, force: true });
  }
}

/** Whether a file looks like an archive readImage can read (tar, gzip or zstd). */
export async function isArchive(path) {
  return Boolean(await sniff(path).catch(() => null));
}
