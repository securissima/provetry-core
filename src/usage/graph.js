// SPDX-License-Identifier: AGPL-3.0-only
// Who depends on whom, from the lock files: the edges between components and the project's own direct
// dependencies (the roots). Used by the import analysis: a component that no path from the code reaches
// is never loaded. `complete` says whether the file gives every edge (a requirements.txt without
// pip-compile's "# via" comments does not: nothing is concluded from it then).
import { readFile } from 'node:fs/promises';
import { basename, dirname } from 'node:path';
import { makePurl, normalizePypi } from '../purl.js';
import { manifestDirectNames } from '../lockfiles/manifests.js';

/**
 * @typedef {{ ecosystem: string, complete: boolean, nodes: Map<string, { name: string, type: string, aliases?: Set<string> }>,
 *   edges: Map<string, Set<string>>, roots: Set<string>, external: Set<string>, used: Map<string, string>, unsure: Set<string>,
 *   bins?: Map<string, string[]>, autoload?: Map<string, { prefixes: string[] }> }} Graph
 * external: what comes in through code outside the repository (a linked folder): never concluded.
 * used: loaded whatever the code says (install scripts, framework auto-discovery), with the reason.
 * unsure: no conclusion of absence for these.
 */

function graph(ecosystem) {
  return { ecosystem, complete: true, nodes: new Map(), edges: new Map(), roots: new Set(), external: new Set(), used: new Map(), unsure: new Set() };
}
function node(g, type, name, version) {
  const purl = makePurl(type, name, version);
  if (!g.nodes.has(purl)) g.nodes.set(purl, { name, type });
  if (!g.edges.has(purl)) g.edges.set(purl, new Set());
  return purl;
}
const alias = (g, purl, name) => { const n = g.nodes.get(purl); if (n && name && name !== n.name) (n.aliases ??= new Set()).add(name); };
const edge = (g, from, to) => { if (from && to && from !== to) g.edges.get(from)?.add(to); };

// ---------- npm (package-lock v2/v3) ----------
export function npmGraph(text) {
  const lock = JSON.parse(text);
  const g = graph('npm');
  const pk = lock.packages;
  if (!pk || typeof pk !== 'object') { g.complete = false; return g; }
  const nameOf = (key, p) => p.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
  const purlOf = new Map();
  for (const [key, p] of Object.entries(pk)) {
    if (!key.includes('node_modules/') || p.link || !p.version) continue;
    purlOf.set(key, node(g, 'npm', nameOf(key, p), p.version));
    // Installed under another name ("alias": "npm:real@1"): the code imports the alias.
    alias(g, purlOf.get(key), key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length));
    if (p.hasInstallScript) g.used.set(purlOf.get(key), 'runs a script when installed');
    if (p.bin && typeof p.bin === 'object') (g.bins ??= new Map()).set(purlOf.get(key), Object.keys(p.bin));
    else if (typeof p.bin === 'string') (g.bins ??= new Map()).set(purlOf.get(key), [nameOf(key, p).replace(/^@[^/]+\//, '')]);
  }
  // Node's resolution: from the folder of the package, up through every parent node_modules.
  const resolveFrom = (from, name) => {
    let base = from;
    for (;;) {
      let k = `${base ? `${base}/` : ''}node_modules/${name}`;
      let p = pk[k];
      if (p?.link && p.resolved) { k = p.resolved; p = pk[k]; }
      if (p && purlOf.has(k)) return purlOf.get(k);
      if (!base) return null;
      const i = base.lastIndexOf('/node_modules/');
      base = i >= 0 ? base.slice(0, i) : base.startsWith('node_modules/') ? '' : '';
    }
  };
  const depsOf = (p) => Object.keys({ ...(p.dependencies ?? {}), ...(p.optionalDependencies ?? {}), ...(p.peerDependencies ?? {}) });
  for (const [key, p] of Object.entries(pk)) {
    if (p.link) continue;
    const isProject = !key.includes('node_modules/'); // the root ("") and the workspace packages
    for (const d of depsOf(p).concat(isProject ? Object.keys(p.devDependencies ?? {}) : [])) {
      const to = resolveFrom(key, d);
      if (!to) continue;
      if (isProject) {
        g.roots.add(to);
        // A linked folder outside the repository: its code is not read here.
        if (key.startsWith('../') || key.startsWith('/')) g.external.add(to);
      } else edge(g, purlOf.get(key), to);
    }
  }
  return g;
}

// ---------- pnpm (v6, v9) ----------
const pnpmVersion = (v) => String(v ?? '').replace(/^'|'$/g, '').replace(/\(.*$/, '').trim();
export function pnpmGraph(text) {
  const g = graph('npm');
  const key = /^ {2}'?\/?((?:@[^/\s]+\/)?[^@\s'(]+)@([^:\s'(]+)(?:\([^)]*\))*'?:\s*(\{\})?\s*$/;
  let top = null; let inDeps = false; let cur = null; let section = false; let sectionIndent = -1; let entry = null;
  // "alias: real@1.2.3" (or "real@1.2.3(peer)"): the package is "real", imported as "alias".
  const target = (name, v) => {
    const ver = pnpmVersion(v);
    const at = ver.lastIndexOf('@');
    if (at > 0) { const purl = node(g, 'npm', ver.slice(0, at), ver.slice(at + 1)); alias(g, purl, name); return purl; }
    return node(g, 'npm', name, ver);
  };
  const addRoot = (name, v) => { const ver = pnpmVersion(v); if (ver && !/^(link|file|workspace):/.test(ver)) g.roots.add(target(name, v)); };
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      top = line.replace(/:.*$/, '').trim(); cur = null; inDeps = false; entry = null;
      section = /^(devDependencies|dependencies|optionalDependencies)$/.test(top); sectionIndent = 0;
      continue;
    }
    if (top === 'importers' || (section && sectionIndent === 0)) {
      const head = /^( *)(devDependencies|dependencies|optionalDependencies):\s*$/.exec(line);
      if (top === 'importers' && head) { section = true; sectionIndent = head[1].length; entry = null; continue; }
      if (!section || indent <= sectionIndent) { section = false; continue; }
      const m = /^ *'?(@?[^:'\s]+)'?:\s*(.*)$/.exec(line);
      if (!m) continue;
      if (indent === sectionIndent + 2) { if (m[2] && !m[2].startsWith('{')) addRoot(m[1], m[2]); entry = m[2] ? null : m[1]; }
      else if (entry && m[1] === 'version') addRoot(entry, m[2]);
      continue;
    }
    if (top === 'packages' || top === 'snapshots') {
      const k = key.exec(line);
      if (k) { cur = node(g, 'npm', k[1], k[2]); inDeps = false; continue; }
      if (indent === 4) {
        inDeps = /^ {4}(dependencies|optionalDependencies):\s*$/.test(line);
        if (/^ {4}requiresBuild: true/.test(line) && cur) g.used.set(cur, 'runs a script when installed');
      }
      else if (indent === 6 && inDeps && cur) {
        const d = /^ {6}'?(@?[^:'\s]+)'?:\s*'?([^'\s]+)/.exec(line);
        if (d) edge(g, cur, target(d[1], d[2]));
      }
    }
  }
  return g;
}

// ---------- yarn (v1 and Berry) ----------
export async function yarnGraph(text, dir) {
  const g = graph('npm');
  const byDescriptor = new Map(); // "name@range" → purl
  const pending = []; // [purl, "name@range"]
  for (const block of text.split(/\r?\n(?=\S)/)) {
    const lines = block.split(/\r?\n/);
    const head = lines[0].trim();
    if (!head || head.startsWith('#') || head.startsWith('__metadata')) continue;
    const descs = head.replace(/:$/, '').split(',').map((d) => d.trim().replace(/^"|"$/g, ''));
    const first = descs[0];
    const at = first.indexOf('@', 1);
    let name = at > 0 ? first.slice(0, at) : first;
    const range = at > 0 ? first.slice(at + 1) : '';
    if (/^(workspace|link|portal|file|patch):/.test(range) || range.includes('@workspace:')) continue;
    if (range.startsWith('npm:')) { const a = range.slice(4); const i = a.indexOf('@', 1); if (i > 0 && !/^[\^~<>=\d*]/.test(a)) name = a.slice(0, i); }
    const v = lines.map((l) => /^ {2}version:? "?([^"\s]+)"?/.exec(l)).find(Boolean);
    if (!v) continue;
    const purl = node(g, 'npm', name, v[1]);
    alias(g, purl, at > 0 ? first.slice(0, at) : first);
    for (const d of descs) byDescriptor.set(d, purl);
    let inDeps = false;
    for (const l of lines.slice(1)) {
      if (/^ {2}\S/.test(l)) { inDeps = /^ {2}(dependencies|optionalDependencies):?\s*$/.test(l); continue; }
      const m = inDeps && /^ {4}"?(@?[^"\s:]+)"?:? "?([^"]+?)"?\s*$/.exec(l);
      if (m) pending.push([purl, `${m[1]}@${m[2]}`]);
    }
  }
  for (const [from, d] of pending) {
    const to = byDescriptor.get(d) ?? byDescriptor.get(d.replace(/@(?!npm:)([^@]*)$/, '@npm:$1'));
    if (to) edge(g, from, to); else g.complete = false;
  }
  const names = await manifestDirectNames(dir, 'yarn.lock');
  if (!names) g.complete = false;
  else for (const [purl, n] of g.nodes) if (names.has(n.name)) g.roots.add(purl);
  return g;
}

// ---------- TOML [[package]] lists: Cargo.lock, poetry.lock, uv.lock ----------
function tomlPackages(text) {
  const out = [];
  let cur = null; let sub = null; let arr = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '[[package]]') { cur = { deps: [] }; out.push(cur); sub = null; arr = null; continue; }
    if (/^\[/.test(line)) { sub = /^\[package\.(dependencies|dev-dependencies|optional-dependencies(?:\.[^\]]+)?)\]$/.exec(line)?.[1] ?? 'other'; arr = null; continue; }
    if (!cur) continue;
    if (arr) {
      for (const m of line.matchAll(/name\s*=\s*"([^"]+)"|^"([^"]+)"/g)) cur.deps.push(m[1] ?? m[2]);
      if (/^\]/.test(line) || /\]\s*,?\s*$/.test(line) && !/name\s*=/.test(line)) arr = null;
      continue;
    }
    const kv = /^([A-Za-z0-9_.-]+|"[^"]+")\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const k = kv[1].replace(/^"|"$/g, ''); const v = kv[2];
    if (sub === null || sub === undefined) {
      if (k === 'name' || k === 'version') cur[k] = v.replace(/^"|"$/g, '');
      else if (k === 'source') cur.source = v;
      else if (k === 'dependencies' || k === 'dev-dependencies' || k === 'optional-dependencies') {
        for (const m of v.matchAll(/name\s*=\s*"([^"]+)"|"([^"]+)"/g)) cur.deps.push(m[1] ?? m[2]);
        if (/^\[/.test(v) && !/\]\s*$/.test(v)) arr = true;
      }
    } else if (sub === 'dependencies' || sub.startsWith('optional') || sub === 'dev-dependencies') cur.deps.push(k);
  }
  return out;
}

export async function cargoGraph(text, dir) {
  const g = graph('cargo');
  const pkgs = tomlPackages(text).filter((p) => p.name && p.version);
  const byName = new Map();
  for (const p of pkgs) {
    p.purl = p.source ? node(g, 'cargo', p.name, p.version) : null; // no source: a crate of this workspace
    (byName.get(p.name) ?? byName.set(p.name, []).get(p.name)).push(p);
  }
  // "name", "name version" or "name version (source)"
  const target = (d) => {
    const [n, v] = d.split(' ');
    const c = byName.get(n) ?? [];
    return (v ? c.find((p) => p.version === v) : c[0]) ?? null;
  };
  for (const p of pkgs) {
    for (const d of p.deps) {
      const t = target(d);
      if (!t?.purl) continue;
      if (p.purl) edge(g, p.purl, t.purl); else g.roots.add(t.purl);
    }
  }
  if (!pkgs.some((p) => !p.source)) {
    const names = await manifestDirectNames(dir, 'Cargo.lock');
    if (!names) g.complete = false;
    else for (const p of pkgs) if (p.purl && names.has(p.name)) g.roots.add(p.purl);
  }
  return g;
}

export async function pythonLockGraph(text, dir, lockName) {
  const g = graph('pypi');
  const pkgs = tomlPackages(text).filter((p) => p.name && p.version);
  const byName = new Map();
  const project = [];
  for (const p of pkgs) {
    // uv lists the project itself (virtual or editable source): its dependencies are the roots.
    if (/virtual|editable/.test(p.source ?? '')) { project.push(p); continue; }
    p.purl = node(g, 'pypi', normalizePypi(p.name), p.version);
    byName.set(normalizePypi(p.name), p);
  }
  for (const p of pkgs) {
    for (const d of p.deps) {
      const t = byName.get(normalizePypi(d.split(/[\s[<>=~!;]/)[0]));
      if (!t) continue;
      if (p.purl) edge(g, p.purl, t.purl); else g.roots.add(t.purl);
    }
  }
  if (!project.length) {
    const names = await manifestDirectNames(dir, lockName);
    if (!names) g.complete = false;
    else for (const [n, p] of byName) if (names.has(n)) g.roots.add(p.purl);
  }
  return g;
}

// ---------- requirements.txt: edges only from pip-compile's "# via" comments ----------
export function requirementsGraph(text) {
  const g = graph('pypi');
  const pins = [];
  let last = null;
  let sawVia = false;
  for (const raw of text.split(/\r?\n/)) {
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\]+)/.exec(raw.trim());
    if (m) { last = { name: normalizePypi(m[1]), purl: node(g, 'pypi', normalizePypi(m[1]), m[2]), via: [] }; pins.push(last); }
    const inline = /#\s*via\s+(.+)$/.exec(raw);
    const cont = /^\s+#\s+(?!via\b)(\S+)/.exec(raw);
    if (inline && last) { sawVia = true; last.via.push(...inline[1].split(/[\s,]+/).filter(Boolean)); }
    else if (/^\s+#\s+via\s*$/.test(raw)) sawVia = true;
    else if (cont && last && sawVia) last.via.push(cont[1]);
  }
  if (!sawVia) { g.complete = false; return g; }
  const byName = new Map(pins.map((p) => [p.name, p]));
  for (const p of pins) {
    for (const v of p.via) {
      if (/^-[rc]$/.test(v) || /\.(txt|in|toml|cfg)$/.test(v)) { g.roots.add(p.purl); continue; }
      const from = byName.get(normalizePypi(v.replace(/\[.*$/, '')));
      if (from) edge(g, from.purl, p.purl);
    }
  }
  return g;
}

// ---------- Composer ----------
export async function composerGraph(text, dir) {
  const g = graph('composer');
  const lock = JSON.parse(text);
  const all = [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])];
  const byName = new Map();
  g.autoload = new Map();
  for (const p of all) {
    if (!p.name || !p.version) continue;
    const purl = node(g, 'composer', p.name, String(p.version).replace(/^v(?=\d)/, ''));
    byName.set(p.name.toLowerCase(), purl);
    const a = p.autoload ?? {};
    const psr4 = Object.keys(a['psr-4'] ?? {}).map((x) => x.replace(/\\+$/, ''));
    const psr0 = Object.keys(a['psr-0'] ?? {}).map((x) => x.replace(/[\\_]+$/, ''));
    g.autoload.set(purl, { prefixes: [...psr4, ...psr0].filter(Boolean) });
    // Loaded without any "use" in the project: on every request (autoload "files"), by Composer itself
    // (plugins), by the framework (Laravel package discovery, Symfony bundles).
    if (Array.isArray(a.files) && a.files.length) g.used.set(purl, 'loaded by Composer on every request (autoload "files")');
    else if (p.type === 'composer-plugin' || p.type === 'composer-installer') g.used.set(purl, 'a Composer plugin: runs when installing');
    else if (p.extra?.laravel) g.used.set(purl, 'registered by Laravel package discovery');
    else if (p.type === 'symfony-bundle') g.unsure.add(purl);
    // No namespace to look for, class names without one ("Twig_"), or an implementation found at run time.
    if (!psr4.length && !psr0.length || psr0.some((x) => !x.includes('\\')) || (Array.isArray(a.classmap) && a.classmap.length) || Object.keys(p.provide ?? {}).length) g.unsure.add(purl);
  }
  for (const p of all) {
    const from = byName.get(String(p.name).toLowerCase());
    for (const d of Object.keys(p.require ?? {})) edge(g, from, byName.get(d.toLowerCase()));
  }
  const names = await manifestDirectNames(dir, 'composer.lock');
  if (!names) g.complete = false;
  else for (const n of names) { const p = byName.get(n.toLowerCase()); if (p) g.roots.add(p); }
  return g;
}

// ---------- Bundler ----------
export function gemfileGraph(text) {
  const g = graph('gem');
  const byName = new Map();
  const pending = [];
  let section = null; let cur = null;
  for (const raw of text.split(/\r?\n/)) {
    if (/^\S/.test(raw)) { section = raw.trim(); cur = null; continue; }
    if (section === 'GEM' || section === 'GIT' || section === 'PATH') {
      const spec = /^ {4}([^\s(]+) \(([^)]+)\)$/.exec(raw);
      if (spec) { const v = spec[2].replace(/-[a-z].*$/, ''); cur = node(g, 'gem', spec[1], v); byName.set(spec[1], cur); continue; }
      const dep = /^ {6}([^\s(]+)/.exec(raw);
      if (dep && cur) pending.push([cur, dep[1]]);
    } else if (section === 'DEPENDENCIES') {
      const d = /^ {2}([^\s(!]+)/.exec(raw);
      if (d) pending.push([null, d[1]]);
    }
  }
  for (const [from, name] of pending) {
    const to = byName.get(name);
    if (!to) continue;
    if (from) edge(g, from, to); else g.roots.add(to);
  }
  return g;
}

// ---------- NuGet packages.lock.json ----------
export function nugetGraph(text) {
  const g = graph('nuget');
  const lock = JSON.parse(text);
  const pending = [];
  const byName = new Map();
  for (const deps of Object.values(lock.dependencies ?? {})) {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (!d?.resolved || d.type === 'Project') continue;
      const purl = node(g, 'nuget', name, d.resolved);
      byName.set(name.toLowerCase(), purl);
      if (d.type === 'Direct') g.roots.add(purl);
      for (const dn of Object.keys(d.dependencies ?? {})) pending.push([purl, dn]);
    }
  }
  for (const [from, n] of pending) edge(g, from, byName.get(n.toLowerCase()));
  return g;
}

// ---------- Java: no edges (Gradle lock files and pom.xml do not give them): evidence of use only ----------
export async function javaGraph(path) {
  const { readLockFile } = await import('../lockfiles/index.js');
  const g = graph('maven');
  g.complete = false;
  for (const c of await readLockFile(path)) { node(g, 'maven', c.name, c.version); if (c.direct) g.roots.add(c.purl); }
  return g;
}

/** The graph of one lock file, or null for a format without one here (go.mod: govulncheck does better). */
export async function readGraph(path) {
  const text = await readFile(path, 'utf8');
  const dir = dirname(path);
  const name = basename(path);
  if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') return npmGraph(text);
  if (name === 'pnpm-lock.yaml') return pnpmGraph(text);
  if (name === 'yarn.lock') return yarnGraph(text, dir);
  if (name === 'Cargo.lock') return cargoGraph(text, dir);
  if (name === 'poetry.lock' || name === 'uv.lock') return pythonLockGraph(text, dir, name);
  if (name === 'requirements.txt') return requirementsGraph(text);
  if (name === 'composer.lock') return composerGraph(text, dir);
  if (name === 'Gemfile.lock') return gemfileGraph(text);
  if (name === 'packages.lock.json') return nugetGraph(text);
  if (name === 'gradle.lockfile' || name === 'buildscript-gradle.lockfile' || name === 'pom.xml') return javaGraph(path);
  return null; // Pipfile.lock has no edges; go.mod is for govulncheck
}
