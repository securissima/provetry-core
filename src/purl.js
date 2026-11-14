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

const OS_ECOSYSTEM = { debian: 'Debian', ubuntu: 'Ubuntu', alpine: 'Alpine' };

/**
 * How OSV.dev names the ecosystem of an operating-system package, with its release ("Debian:12",
 * "Ubuntu:22.04:LTS", "Alpine:v3.19"), and the package name advisories use (the source package for
 * Debian and Ubuntu). Null for other purls, or when the release is unknown.
 */
export function osvOsPackage(purl) {
  const p = parsePurl(purl);
  if (!p || !p.version || !['deb', 'apk'].includes(p.type)) return null;
  const ns = (p.namespace ?? '').toLowerCase();
  const base = OS_ECOSYSTEM[ns];
  if (!base) return null;
  const q = purlQualifiers(purl);
  const release = String(q.distro ?? '').replace(new RegExp(`^${ns}-`), '');
  if (!release) return null;
  let ecosystem;
  if (ns === 'debian') ecosystem = `Debian:${release.split('.')[0]}`;
  else if (ns === 'ubuntu') { const [y, m] = release.split('.').map(Number); ecosystem = `Ubuntu:${release}${m === 4 && y % 2 === 0 ? ':LTS' : ''}`; }
  else ecosystem = `Alpine:v${release.split('.').slice(0, 2).join('.')}`;
  return { ecosystem, base, name: q.upstream || p.name, version: p.version };
}
