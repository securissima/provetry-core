// SPDX-License-Identifier: AGPL-3.0-only
// What is installed in a root filesystem, from the package databases it carries: dpkg (Debian, Ubuntu,
// distroless images), apk (Alpine), opkg (OpenWrt, Yocto), plus the Python distributions and Node.js
// packages installed by language package managers. Each parser takes the text of one database file.
import { makeOsPurl, makePurl, normalizePypi } from '../purl.js';

/** os-release: { id, idLike, versionId, codename, ubuntuCodename, prettyName }. */
export function parseOsRelease(text) {
  const kv = {};
  for (const line of String(text).split('\n')) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (m) kv[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return {
    id: (kv.ID ?? '').toLowerCase(),
    idLike: (kv.ID_LIKE ?? '').toLowerCase().split(/\s+/).filter(Boolean),
    versionId: kv.VERSION_ID ?? '',
    codename: (kv.VERSION_CODENAME ?? '').toLowerCase(),
    ubuntuCodename: (kv.UBUNTU_CODENAME ?? '').toLowerCase(),
    prettyName: kv.PRETTY_NAME ?? '',
  };
}

// Releases by code name, for derivatives that only say which release they follow.
// Released ones only: a derivative of Debian testing must not be looked up as a stable release.
const DEBIAN_CODENAMES = { stretch: '9', buster: '10', bullseye: '11', bookworm: '12', trixie: '13' };
const UBUNTU_CODENAMES = { xenial: '16.04', bionic: '18.04', focal: '20.04', jammy: '22.04', noble: '24.04', oracular: '24.10', plucky: '25.04', questing: '25.10' };

/**
 * The purl namespace and "distro" qualifier of a release, and whether its packages can be looked up:
 *  - Debian, Ubuntu, Alpine: by release ("debian-12", "ubuntu-22.04", "3.19.1");
 *  - their derivatives (Raspberry Pi OS, Linux Mint…) keep their own namespace, with the parent release
 *    they follow as the distro qualifier ("pkg:deb/raspbian/…?distro=debian-12"): looked up as the parent's;
 *  - Wolfi and Chainguard: rolling, no release.
 * `lookup` is false, with a `why`, when no public advisory database covers the release.
 */
export function distroOf(os) {
  if (!os?.id) return null;
  const id = os.id;
  const label = os.prettyName || id;
  if (id === 'wolfi' || id === 'chainguard') return { namespace: id, family: id, distro: '', lookup: true, base: id };
  if (id === 'debian' || id === 'ubuntu') {
    // Every stable Debian release has a VERSION_ID: without one, it is testing or unstable, which the
    // advisories of stable releases do not cover. Ubuntu's development release has one too.
    const v = os.versionId || (id === 'ubuntu' ? UBUNTU_CODENAMES[os.codename] : '') || '';
    if (!v) return { namespace: id, family: id, distro: '', lookup: false, why: `${label} names no release (testing or unstable): its packages are listed but not looked up` };
    return { namespace: id, family: id, distro: `${id}-${v}`, lookup: true, base: id };
  }
  if (id === 'alpine') {
    // edge says VERSION_ID=3.21_alpha…: a development snapshot, not a release OSV covers.
    if (!/^\d+\.\d+(\.\d+)?$/.test(os.versionId)) return { namespace: id, family: id, distro: os.versionId, lookup: false, why: `${label} is not a stable Alpine release (edge): its packages are listed but not looked up` };
    return { namespace: id, family: id, distro: os.versionId, lookup: true, base: id };
  }
  // A derivative: looked up as the release it follows, when it says which.
  const ubuntu = UBUNTU_CODENAMES[os.ubuntuCodename] ?? (os.idLike.includes('ubuntu') ? UBUNTU_CODENAMES[os.codename] : undefined);
  if (ubuntu) return { namespace: id, family: 'ubuntu', distro: `ubuntu-${ubuntu}`, lookup: true, base: 'ubuntu', derived: `${label} is looked up as Ubuntu ${ubuntu}: packages of its own are not covered, and its rebuilt versions compare only approximately with Ubuntu's fixes` };
  const debian = os.idLike.includes('debian') ? DEBIAN_CODENAMES[os.codename] : undefined;
  if (debian) return { namespace: id, family: 'debian', distro: `debian-${debian}`, lookup: true, base: 'debian', derived: `${label} is looked up as Debian ${debian}: packages of its own are not covered, and its rebuilt versions (such as +rpi1) compare only approximately with Debian's fixes` };
  const family = ['debian', 'ubuntu', 'alpine'].find((x) => os.idLike.includes(x)) ?? id;
  return { namespace: id, family, distro: os.versionId ? `${id}-${os.versionId}` : '', lookup: false, why: `no public advisory database covers ${label}: its packages are listed but not looked up` };
}

/** Whether a dpkg or opkg Status field means the package's files are on disk ("install ok installed", "… unpacked"…). */
const onDisk = (status) => !status || !/\b(not-installed|config-files)\s*$/.test(status);
// A binNMU ("+b1") rebuilds the same source: advisories name the source version.
const sourceVersion = (v) => v.replace(/\+b\d+$/, '');

const paragraphs = (text) => String(text).replace(/\r/g, '').split(/\n\s*\n/);

/** A dpkg status file (or one file of status.d/ in distroless images): the packages actually installed. */
export function parseDpkgStatus(text, source, dist) {
  const out = [];
  for (const para of paragraphs(text)) {
    const f = {};
    let last = null;
    for (const line of para.split('\n')) {
      if (/^\s/.test(line)) { if (last) f[last] += `\n${line.trim()}`; continue; }
      const i = line.indexOf(':');
      if (i > 0) { last = line.slice(0, i).trim().toLowerCase(); f[last] = line.slice(i + 1).trim(); }
    }
    if (!f.package || !f.version) continue;
    // status.d files have no Status field (installed by construction); a status file lists removed packages too.
    if (!onDisk(f.status)) continue;
    // The source package, with its version when it differs: advisories are written against the source.
    const src = /^(\S+)(?:\s+\(([^)]+)\))?/.exec(f.source ?? '');
    const srcName = src?.[1] ?? f.package;
    const srcVer = src?.[2] ?? sourceVersion(f.version);
    const upstream = srcName !== f.package || srcVer !== f.version ? (srcVer !== f.version ? `${srcName}@${srcVer}` : srcName) : '';
    const ns = dist?.namespace ?? 'debian';
    out.push({
      type: 'deb', name: f.package, version: f.version, scope: 'required', sources: [source],
      purl: makeOsPurl('deb', ns, f.package, f.version, { arch: f.architecture, distro: dist?.distro, upstream }),
      ...(f.license ? { license: f.license } : {}),
    });
  }
  return out;
}

/** Alpine's installed database (lib/apk/db/installed). */
export function parseApkInstalled(text, source, dist) {
  const out = [];
  for (const para of paragraphs(text)) {
    const f = {};
    for (const line of para.split('\n')) { const m = /^([A-Za-z]):(.*)$/.exec(line); if (m && !(m[1] in f)) f[m[1]] = m[2]; }
    if (!f.P || !f.V) continue;
    const upstream = f.o && f.o !== f.P ? f.o : '';
    out.push({
      type: 'apk', name: f.P, version: f.V, scope: 'required', sources: [source],
      purl: makeOsPurl('apk', dist?.namespace ?? 'alpine', f.P, f.V, { arch: f.A, distro: dist?.distro?.replace(/^alpine-/, ''), upstream }),
      ...(f.L ? { license: f.L } : {}),
    });
  }
  return out;
}

/** opkg's status file (OpenWrt, Yocto with ipk packages). No public advisory database covers them: listed, not looked up. */
export function parseOpkgStatus(text, source, dist) {
  const out = [];
  for (const para of paragraphs(text)) {
    const f = {};
    for (const line of para.split('\n')) { const i = line.indexOf(':'); if (i > 0 && !/^\s/.test(line)) f[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim(); }
    if (!f.package || !f.version || !onDisk(f.status)) continue;
    out.push({
      type: 'opkg', name: f.package, version: f.version, scope: 'required', sources: [source],
      purl: makeOsPurl('opkg', dist?.namespace || 'openwrt', f.package, f.version, { arch: f.architecture, distro: dist?.distro }),
    });
  }
  return out;
}

/** A Python distribution's METADATA (or PKG-INFO): its name and version. */
export function parsePythonMetadata(text, source) {
  const name = /^Name:\s*(.+)$/m.exec(text)?.[1]?.trim();
  const version = /^Version:\s*(.+)$/m.exec(text)?.[1]?.trim();
  if (!name || !version) return [];
  return [{ type: 'pypi', name: normalizePypi(name), version, purl: makePurl('pypi', name, version), scope: 'required', sources: [source] }];
}

/** An installed Node.js package (node_modules/<name>/package.json). */
export function parseNodePackage(text, source) {
  let j;
  try { j = JSON.parse(text); } catch { return []; }
  if (typeof j?.name !== 'string' || typeof j?.version !== 'string' || !j.name || j.private) return [];
  return [{ type: 'npm', name: j.name, version: j.version, purl: makePurl('npm', j.name, j.version), scope: 'required', sources: [source] }];
}
