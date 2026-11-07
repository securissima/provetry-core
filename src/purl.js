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
