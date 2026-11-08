// SPDX-License-Identifier: AGPL-3.0-only
// Import analysis, every ecosystem with a lock file that gives its dependency graph: is a component loaded
// by the product's own code? A component is
//   "imported"   when a file of the project imports it (file and line given);
//   "loaded"     when an imported component depends on it, directly or not (the chain given);
//   "not_loaded" when no path leads to it from anything the code imports or names (the chain that brings
//                it in is given): its code never runs, whatever its vulnerabilities;
//   "unknown"    when the analysis cannot tell (graph incomplete, import names not sure).
// It is a level above govulncheck's function-level answer: "loaded" says nothing about the vulnerable
// function being called. And it does not see code loaded by name at run time from data (a plugin chosen in
// a database, for example); names written in the project's own files are counted as uses.
import { dirname, join, relative } from 'node:path';
import { readFile } from 'node:fs/promises';
import { findLockFiles } from '../lockfiles/index.js';
import { normalizePypi } from '../purl.js';
import { readGraph } from './graph.js';
import { sourceFiles, jsImports, pyImports, installedPyModules, PYPI_MODULES, rsImports, cargoRenames, rbImports, phpImports, csImports } from './imports.js';

const ORDER = { imported: 3, loaded: 2, unknown: 1, not_loaded: 0 };
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** For each component of the graph: { used, evidence, sure } from what the code imports. */
async function directUse(g, dir, files) {
  const out = new Map();
  const set = (purl, used, evidence, sure) => out.set(purl, { used, evidence, sure });
  if (g.ecosystem === 'npm') {
    const { imported, named, scripts } = await jsImports(dir, files);
    for (const [purl, n] of g.nodes) {
      if (imported.has(n.name)) { set(purl, true, imported.get(n.name).map((e) => ({ ...e, how: 'imported' })), true); continue; }
      if (named.has(n.name)) { set(purl, true, named.get(n.name).map((e) => ({ ...e, how: 'named' })), true); continue; }
      const bins = [...(g.bins?.get(purl) ?? []), n.name.replace(/^@[^/]+\//, '')];
      const s = scripts.find((x) => bins.some((b) => new RegExp(`(?:^|[\\s;&|(/])${escapeRe(b)}(?:$|[\\s;&|)])`).test(x.text)));
      set(purl, Boolean(s), s ? [{ file: s.file, line: 1, how: 'run by a script' }] : [], true);
    }
  } else if (g.ecosystem === 'pypi') {
    const { imported } = await pyImports(dir, files);
    const installed = await installedPyModules(dir);
    for (const [purl, n] of g.nodes) {
      const dist = normalizePypi(n.name);
      const sure = installed.get(dist) ?? PYPI_MODULES[dist] ?? null;
      const guess = [dist.replace(/-/g, '_'), dist.replace(/[-.]/g, '_')];
      const hit = [...(sure ?? []), ...guess].find((m) => imported.has(m));
      set(purl, Boolean(hit), hit ? imported.get(hit).map((e) => ({ ...e, how: 'imported', as: hit })) : [], Boolean(sure));
    }
  } else if (g.ecosystem === 'cargo') {
    const { imported } = await rsImports(dir, files);
    const renames = new Map();
    for (const f of files.filter((x) => /(?:^|\/)Cargo\.toml$/.test(x))) {
      try { for (const [alias, real] of cargoRenames(await readFile(join(dir, f), 'utf8'))) renames.set(real, [...(renames.get(real) ?? []), alias]); } catch { /* unreadable */ }
    }
    for (const [purl, n] of g.nodes) {
      const names = [n.name.replace(/-/g, '_'), ...(renames.get(n.name) ?? [])];
      const hit = names.find((x) => imported.has(x));
      set(purl, Boolean(hit), hit ? imported.get(hit).map((e) => ({ ...e, how: 'used', as: hit })) : [], true);
    }
  } else if (g.ecosystem === 'composer') {
    const { imported } = await phpImports(dir, files);
    const names = [...imported.keys()];
    for (const [purl] of g.nodes) {
      const a = g.autoload?.get(purl) ?? { prefixes: [], files: false, classmap: false };
      if (a.files) { set(purl, true, [{ file: 'composer.lock', line: 1, how: 'loaded by Composer on every request (autoload "files")' }], true); continue; }
      const hit = names.find((x) => a.prefixes.some((p) => x === p || x.startsWith(`${p}\\`)));
      set(purl, Boolean(hit), hit ? imported.get(hit).map((e) => ({ ...e, how: 'used', as: hit })) : [], a.prefixes.length > 0 && !a.classmap);
    }
  } else if (g.ecosystem === 'gem') {
    const { imported, bundlerRequire } = await rbImports(dir, files);
    for (const [purl, n] of g.nodes) {
      if (bundlerRequire && g.roots.has(purl)) { set(purl, true, [{ ...bundlerRequire, how: 'required by Bundler.require' }], true); continue; }
      const cands = [n.name, n.name.replace(/-/g, '/'), n.name.replace(/-/g, '_')];
      const hit = [...imported.keys()].find((r) => cands.some((c) => r === c || r.startsWith(`${c}/`)));
      set(purl, Boolean(hit), hit ? imported.get(hit).map((e) => ({ ...e, how: 'required', as: hit })) : [], false);
    }
  } else if (g.ecosystem === 'nuget') {
    const { imported } = await csImports(dir, files);
    const names = [...imported.keys()];
    for (const [purl, n] of g.nodes) {
      const hit = names.find((x) => x === n.name || x.startsWith(`${n.name}.`));
      set(purl, Boolean(hit), hit ? imported.get(hit).map((e) => ({ ...e, how: 'using', as: hit })) : [], false);
    }
  }
  return out;
}

/** Breadth-first from `starts`: predecessor of each node reached (to give the chain as evidence). */
function walk(g, starts) {
  const prev = new Map(starts.map((s) => [s, null]));
  const queue = [...starts];
  while (queue.length) {
    const k = queue.shift();
    for (const d of g.edges.get(k) ?? []) if (!prev.has(d)) { prev.set(d, k); queue.push(d); }
  }
  return prev;
}
const chainOf = (prev, k) => { const out = []; for (let c = k; c; c = prev.get(c)) out.unshift(c); return out; };
const names = (g, purls) => purls.map((c) => g.nodes.get(c)?.name ?? c);

/** The analysis of one project (one lock file). Map purl → result. */
export async function analyseProject(lockPath, root, { nestedDirs = new Set() } = {}) {
  const g = await readGraph(lockPath);
  if (!g) return null;
  const dir = dirname(lockPath);
  const files = await sourceFiles(dir, { skipNested: nestedDirs });
  const use = await directUse(g, dir, files);
  const used = [...use].filter(([, u]) => u.used).map(([k]) => k);
  const unsure = [...use].filter(([, u]) => !u.used && !u.sure).map(([k]) => k);
  const fromUsed = walk(g, used);
  const fromUnsure = walk(g, unsure);
  const fromRoots = walk(g, [...g.roots]);
  const project = relative(root, lockPath) || lockPath;
  const out = new Map();
  for (const purl of g.nodes.keys()) {
    const u = use.get(purl);
    if (u?.used) out.set(purl, { state: 'imported', evidence: u.evidence, project });
    else if (fromUsed.has(purl)) {
      const c = chainOf(fromUsed, purl);
      out.set(purl, { state: 'loaded', chain: names(g, c), evidence: use.get(c[0])?.evidence ?? [], project });
    } else if (fromUnsure.has(purl) || !g.complete) out.set(purl, { state: 'unknown', project, why: !g.complete ? 'the lock file does not give every dependency link' : 'import names not sure for this ecosystem' });
    else out.set(purl, { state: 'not_loaded', chain: names(g, fromRoots.has(purl) ? chainOf(fromRoots, purl) : [purl]), project, ecosystem: g.ecosystem });
  }
  return out;
}

/**
 * Every project under root. Returns { components: Map purl → result (the most "used" answer across
 * projects), projects, errors }. A component "not_loaded" in one project and loaded in another is loaded.
 */
export async function usage(root) {
  const locks = (await findLockFiles(root)).filter((f) => !/(?:^|\/)(?:go\.mod|Pipfile\.lock)$/.test(f));
  const dirs = new Set(locks.map((f) => dirname(f)));
  const components = new Map();
  const projects = [];
  const errors = [];
  for (const f of locks) {
    const dir = dirname(f);
    const nested = new Set([...dirs].filter((d) => d !== dir && d.startsWith(`${dir}/`)));
    let res;
    try { res = await analyseProject(f, root, { nestedDirs: nested }); } catch (e) { errors.push({ file: relative(root, f), error: e.message }); continue; }
    if (!res) continue;
    projects.push(relative(root, f));
    for (const [purl, r] of res) {
      const prev = components.get(purl);
      if (!prev || ORDER[r.state] > ORDER[prev.state]) components.set(purl, r);
    }
  }
  return { components, projects, errors };
}
