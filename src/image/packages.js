// SPDX-License-Identifier: AGPL-3.0-only
// What is installed in a root filesystem, from the package databases it carries: dpkg (Debian, Ubuntu,
// distroless images), apk (Alpine), opkg (OpenWrt, Yocto), plus the Python distributions and Node.js
// packages installed by language package managers. Each parser takes the text of one database file.
import { makeOsPurl, makePurl, normalizePypi } from '../purl.js';

/** os-release: { id, idLike, versionId, prettyName }. */
export function parseOsRelease(text) {
  const kv = {};
  for (const line of String(text).split('\n')) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (m) kv[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return { id: (kv.ID ?? '').toLowerCase(), idLike: (kv.ID_LIKE ?? '').toLowerCase().split(/\s+/).filter(Boolean), versionId: kv.VERSION_ID ?? '', prettyName: kv.PRETTY_NAME ?? '' };
}

/** The purl namespace and "distro" qualifier for a release: debian-12, ubuntu-22.04, alpine 3.19.1. */
export function distroOf(os) {
  if (!os?.id) return null;
  const family = ['debian', 'ubuntu', 'alpine'].includes(os.id) ? os.id : os.idLike.find((x) => ['debian', 'ubuntu', 'alpine'].includes(x)) ?? os.id;
  // Derivatives (Raspberry Pi OS, Linux Mint…) keep their own name: their packages are not the parent's.
  const namespace = os.id;
  const distro = os.versionId ? `${os.id}-${os.versionId}` : '';
  return { namespace, family, distro };
}

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
    if (f.status && !/\binstalled$/.test(f.status)) continue;
    const src = /^(\S+)(?:\s+\(([^)]+)\))?/.exec(f.source ?? '');
    const upstream = src && src[1] !== f.package ? src[1] : '';
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
    if (!f.package || !f.version || (f.status && !/\binstalled$/.test(f.status))) continue;
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
