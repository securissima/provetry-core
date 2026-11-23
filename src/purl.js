// SPDX-License-Identifier: AGPL-3.0-only
// Package URLs (https://github.com/package-url/purl-spec): the identifier every component carries,
// and the key OSV understands. Only the types Provetry reads are handled.

/** Ecosystem names, as OSV spells them, for each purl type. */
export const OSV_ECOSYSTEM = {
  npm: 'npm',
  pypi: 'PyPI',
  golang: 'Go',
  cargo: 'crates.io',
  composer: 'Packagist',
  gem: 'RubyGems',
  nuget: 'NuGet',
  maven: 'Maven',
};

// purl-spec percent-encoding: everything except unreserved characters (and ':' kept readable is not allowed in names).
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** PyPI names are case-insensitive and treat "_", "." and "-" alike (PEP 503); purl-spec uses lower case and "-". */
export const normalizePypi = (name) => name.toLowerCase().replace(/[-_.]+/g, '-');

/**
 * Builds a purl.
 * @param {string} type purl type (npm, pypi, golang, cargo, composer, gem, nuget, maven)
 * @param {string} name full name as the ecosystem spells it ("@scope/pkg", "vendor/pkg", "github.com/a/b", "group:artifact")
 * @param {string} version
 */
export function makePurl(type, name, version) {
  let namespace = '';
  let base = name;
  if (type === 'npm' && name.startsWith('@') && name.includes('/')) [namespace, base] = [name.slice(0, name.indexOf('/')), name.slice(name.indexOf('/') + 1)];
  else if (type === 'composer' && name.includes('/')) [namespace, base] = name.toLowerCase().split('/', 2);
  else if (type === 'golang' && name.includes('/')) {
    namespace = name.slice(0, name.lastIndexOf('/'));
    base = name.slice(name.lastIndexOf('/') + 1);
  } else if (type === 'maven' && name.includes(':')) [namespace, base] = name.split(':', 2);
  if (type === 'pypi') base = normalizePypi(base);
  const ns = namespace ? `${namespace.split('/').map(enc).join('/')}/` : '';
  return `pkg:${type}/${ns}${enc(base)}${version ? `@${enc(version)}` : ''}`;
}

/** Parses a purl into { type, namespace, name, version } (qualifiers and subpath ignored). Returns null if invalid. */
export function parsePurl(purl) {
  const m = /^pkg:([a-z0-9.+-]+)\/([^?#]+)$/i.exec(String(purl).split(/[?#]/)[0]);
  if (!m) return null;
  const type = m[1].toLowerCase();
  let rest = m[2];
  let version = null;
  const at = rest.lastIndexOf('@');
  if (at > 0) {
    version = decodeURIComponent(rest.slice(at + 1));
    rest = rest.slice(0, at);
  }
  const parts = rest.split('/').map((p) => decodeURIComponent(p));
  const name = parts.pop();
  return { type, namespace: parts.join('/') || null, name, version };
}

/** The ecosystem's own spelling of the package name, from a purl ("@scope/pkg", "vendor/pkg", "github.com/a/b"). */
export function fullName(p) {
  if (!p.namespace) return p.name;
  return p.type === 'maven' ? `${p.namespace}:${p.name}` : `${p.namespace}/${p.name}`;
}

// ---------- Operating-system packages (container images, firmware root filesystems) ----------

/** The qualifiers of a purl ("?arch=amd64&distro=debian-12"), decoded. */
export function purlQualifiers(purl) {
  const q = String(purl).split('#')[0].split('?')[1];
  const out = {};
  if (!q) return out;
  for (const kv of q.split('&')) {
    const eq = kv.indexOf('=');
    if (eq > 0) out[kv.slice(0, eq).toLowerCase()] = decodeURIComponent(kv.slice(eq + 1));
  }
  return out;
}

/** A purl for an operating-system package: pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12. */
export function makeOsPurl(type, namespace, name, version, qualifiers = {}) {
  const q = Object.entries(qualifiers).filter(([, v]) => v).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${enc(v)}`).join('&');
  return `pkg:${type}/${enc(namespace)}/${enc(name)}@${enc(version)}${q ? `?${q}` : ''}`;
}

const OS_ECOSYSTEM = { debian: 'Debian', ubuntu: 'Ubuntu', alpine: 'Alpine', wolfi: 'Wolfi', chainguard: 'Chainguard' };

// RPM distributions OSV.dev carries advisories for, by the names SBOM tools give them (purl namespace and
// distro qualifier: "rhel-9.3", "redhat-9.3", "almalinux-9.3", "alma-9.3", "rocky-9.3", "opensuse-leap-15.6"…).
const RPM_FAMILY = {
  redhat: 'redhat', rhel: 'redhat',
  almalinux: 'almalinux', alma: 'almalinux',
  rocky: 'rocky', 'rocky-linux': 'rocky',
  'opensuse-leap': 'opensuse-leap', 'opensuse.leap': 'opensuse-leap',
  mageia: 'mageia',
};
const RPM_BASE = { redhat: 'Red Hat', almalinux: 'AlmaLinux', rocky: 'Rocky Linux', 'opensuse-leap': 'openSUSE', mageia: 'Mageia' };

/** The source package in an RPM purl's upstream qualifier: { name, version } from "openssl-3.0.7-27.el9.src.rpm" (version "3.0.7-27.el9"). */
function rpmSource(upstream) {
  const m = /^(.+)-([^-]+-[^-]+)\.src\.rpm$/.exec(String(upstream ?? '').trim());
  return m ? { name: m[1], version: m[2] } : null;
}

// Releases OSV.dev carries advisories for: another one would come back empty and look clean.
const RPM_RELEASES = {
  redhat: /^[89]$/,              // later majors are filed per minor release, which a purl does not always give
  almalinux: /^(8|9|10)$/,
  rocky: /^(8|9|10)$/,
  mageia: /^(8|9|10)$/,
};
// Red Hat keeps one ecosystem per repository.
const RHEL_REPOS = { 8: ['baseos', 'appstream', 'crb', 'highavailability', 'resilientstorage', 'supplementary'], 9: ['baseos', 'appstream', 'crb', 'highavailability', 'resilientstorage', 'nfv', 'realtime'] };
// Whose advisories name the source package, always or often: without it, a binary package cannot be asked about.
const RPM_BY_SOURCE = new Set(['rocky', 'opensuse-leap', 'mageia']);

/**
 * An RPM package as OSV.dev's advisories name it. They are the distribution's own advisories (Red Hat,
 * AlmaLinux, Rocky Linux, openSUSE Leap, Mageia), which exist once a fix is published: a vulnerability
 * the distribution has not fixed yet is not in them. Red Hat and AlmaLinux name the binary packages;
 * the others the source package (Rocky Linux: one or the other), which is asked about only when the binary package carries its version
 * (a subpackage with a version of its own, such as perl-Errno, would never compare right).
 * Null (not looked up, and said so) when that cannot be done honestly: no release, a release OSV does not
 * carry, a module stream (its advisories cover every stream of the module), no usable source package.
 */
function osvRpmPackage(p, purl) {
  const q = purlQualifiers(purl);
  const ns = (p.namespace ?? '').toLowerCase();
  const m = /^([a-z][a-z.-]*?)-(\d[\w.]*)$/.exec(String(q.distro ?? '').toLowerCase());
  if (!m) return null;
  const family = RPM_FAMILY[m[1]];
  if (!family) return null;
  // A namespace of another known family contradicts the release: not looked up rather than guessed.
  if (RPM_FAMILY[ns] && RPM_FAMILY[ns] !== family) return null;
  if (/\.module[+_]el/.test(p.version)) return null;
  const major = m[2].split('.')[0];
  let ecosystems;
  if (family === 'opensuse-leap') {
    if (!/^(15\.[2-6]|16\.0)$/.test(m[2])) return null;
    ecosystems = [`openSUSE:Leap ${m[2]}`];
  } else {
    if (!RPM_RELEASES[family].test(major)) return null;
    ecosystems = family === 'redhat' ? RHEL_REPOS[major].map((repo) => `Red Hat:enterprise_linux:${major}::${repo}`) : [`${RPM_BASE[family]}:${major}`];
  }
  const epoch = /^\d+$/.test(String(q.epoch ?? '')) && q.epoch !== '0' ? q.epoch : '';
  const version = epoch && !/^\d+:/.test(p.version) ? `${epoch}:${p.version}` : p.version;
  const src = rpmSource(q.upstream);
  const source = src && src.version === p.version.replace(/^\d+:/, '') ? src.name : '';
  if (RPM_BY_SOURCE.has(family) && !source) return null;
  const names = [...new Set([p.name, source].filter(Boolean))];
  // `family` is the purl's own namespace when it is one of the family's names, so that only a real
  // derivative (another namespace, looked up as its parent's release) is reported as approximate.
  return { ecosystem: ecosystems[0], ecosystems, base: RPM_BASE[family], family: RPM_FAMILY[ns] === family ? ns : family, name: names[0], names, version };
}

/**
 * How OSV.dev names the ecosystem of an operating-system package, with its release ("Debian:12",
 * "Ubuntu:22.04:LTS", "Alpine:v3.19", "Wolfi", "AlmaLinux:9"), and the package name and version advisories
 * use (the source package for Debian and Ubuntu, from the `upstream` qualifier: "openssl" or
 * "zlib@1:1.2.13.dfsg-1"). `ecosystems` and `names` list every spelling to ask (more than one for RPM).
 * A derivative (pkg:deb/raspbian/…?distro=debian-12) is looked up as the release its distro qualifier names.
 * Null for other purls, or when the release is unknown.
 */
export function osvOsPackage(purl) {
  const p = parsePurl(purl);
  if (!p || !p.version) return null;
  if (p.type === 'rpm') return osvRpmPackage(p, purl);
  if (!['deb', 'apk'].includes(p.type)) return null;
  const ns = (p.namespace ?? '').toLowerCase();
  const q = purlQualifiers(purl);
  const distro = String(q.distro ?? '');
  let family = OS_ECOSYSTEM[ns] ? ns : null;
  let release = distro;
  if (p.type === 'deb') {
    const m = /^(debian|ubuntu)-(.+)$/.exec(distro);
    if (!m || (family && family !== m[1])) return null;
    [, family, release] = m;
  } else if (family === 'wolfi' || family === 'chainguard') {
    release = '';
  } else if (family === 'alpine') {
    release = release.replace(/^alpine-/, '');   // Syft writes distro=alpine-3.19.1, purl-spec 3.19.1
    if (!/^\d+\.\d+(\.\d+)?$/.test(release)) return null;
  } else if (family !== 'alpine' || !/^\d+\.\d+(\.\d+)?$/.test(release)) {
    return null;
  }
  let ecosystem;
  if (family === 'debian') ecosystem = `Debian:${release.split('.')[0]}`;
  else if (family === 'ubuntu') { const [y, m] = release.split('.').map(Number); ecosystem = `Ubuntu:${release}${m === 4 && y % 2 === 0 ? ':LTS' : ''}`; }
  else if (family === 'alpine') ecosystem = `Alpine:v${release.split('.').slice(0, 2).join('.')}`;
  else ecosystem = OS_ECOSYSTEM[family];
  const up = String(q.upstream ?? '');
  const at = up.indexOf('@');
  const name = (at > 0 ? up.slice(0, at) : up) || p.name;
  const version = at > 0 ? up.slice(at + 1) : p.version;
  return { ecosystem, ecosystems: [ecosystem], base: OS_ECOSYSTEM[family], family, name, names: [name], version };
}

/** Whether OSV.dev can be asked about a purl: operating-system packages only with a release it covers. */
export function osvQueryable(purl) {
  const p = parsePurl(purl);
  if (!p) return true;   // as before: OSV says what it makes of it
  if (['deb', 'apk', 'opkg', 'rpm'].includes(p.type)) return Boolean(osvOsPackage(purl));
  return true;
}
