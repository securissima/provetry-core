// SPDX-License-Identifier: AGPL-3.0-only
// Import analysis, every ecosystem with a lock file that gives its dependency graph: is a component loaded
// by the product? A component is
//   "imported"   when a file of the repository imports, names or runs it, or when it is loaded whatever
//                the code says (install scripts, framework auto-discovery);
//   "loaded"     when something imported depends on it, directly or not (the chain given);
//   "not_loaded" when no path leads to it from anything used (the chain that brings it in is given);
//   "unknown"    when the analysis cannot tell.
// The dangerous mistake is a false "not_loaded": every doubt goes the other way. The whole repository is
// read for every lock file; nothing is concluded where a file could not be read, where import names are
// not sure, where code lives outside the repository, or where a lock file could not be analysed.
// It stays a level above govulncheck's: "loaded" says nothing about the vulnerable function being called.
import { dirname, relative, resolve } from 'node:path';
import { findLockFiles, readLockFile } from '../lockfiles/index.js';
import { normalizePypi } from '../purl.js';
import { readGraph } from './graph.js';
import { projectFiles, readText, npmPackageOf, jsUse, pyUse, installedPython, PYPI_MODULES, PYPI_NEVER_ABSENT, rsUse, cargoManifest, phpUse, rbUse, csUse } from './imports.js';

const ORDER = { imported: 3, loaded: 2, unknown: 1, not_loaded: 0 };

/** What the repository's files use, per ecosystem, read once. */
async function repoUse(root) {
  const { files, incomplete } = await projectFiles(root);
  const big = [];
  const cache = new Map();
  const once = (k, fn) => cache.get(k) ?? cache.set(k, fn()).get(k);
  return {
    files, incomplete, big,
    npm: () => once('npm', () => jsUse(root, files, big)),
    pypi: () => once('pypi', async () => ({ ...(await pyUse(root, files, big)), installed: await installedPython(root) })),
    cargo: () => once('cargo', async () => {
      const r = await rsUse(root, files, big);
      const renames = new Map();
      let outside = null;
      for (const f of files.filter((x) => /(?:^|\/)Cargo\.toml$/.test(x))) {
        const m = cargoManifest(await readText(root, f) ?? '');
        for (const [a, real] of m.renames) renames.set(real, [...(renames.get(real) ?? []), a]);
        for (const p of m.paths) if (relative(root, resolve(root, dirname(f), p)).startsWith('..')) outside ??= `${f} depends on ${p}, outside the repository`;
      }
      return { ...r, renames, outside };
    }),
    composer: () => once('composer', () => phpUse(root, files, big)),
    gem: () => once('gem', () => rbUse(root, files, big)),
    nuget: () => once('nuget', () => csUse(root, files, big)),
  };
}

/** For each component of the graph: { used, evidence, sure }. `blocked`: nothing can be concluded at all. */
async function directUse(g, repo) {
  const out = new Map();
  const set = (purl, used, evidence, sure) => out.set(purl, { used, evidence, sure });
  let blocked = null;
  if (g.ecosystem === 'npm') {
    const { imported, named, tokens, code } = await repo.npm();
    if (!code) blocked = 'no JavaScript or TypeScript file in the repository';
    const tokenPkgs = new Map();
    for (const [t, ev] of tokens) { const p = npmPackageOf(t); if (p && !tokenPkgs.has(p)) tokenPkgs.set(p, ev); }
    for (const [purl, n] of g.nodes) {
      const names = [n.name, ...(n.aliases ?? [])];
      const hit = (m) => names.map((x) => m.get(x)).find(Boolean);
      const bins = g.bins?.get(purl) ?? [];
      const ev = hit(imported) ?? hit(named) ?? hit(tokenPkgs) ?? bins.map((b) => tokens.get(b)).find(Boolean);
      set(purl, Boolean(ev), ev ?? [], true);
    }
  } else if (g.ecosystem === 'pypi') {
    const { imported, tokens, installed, code } = await repo.pypi();
    if (!code) blocked = 'no Python file in the repository';
    for (const [purl, n] of g.nodes) {
      const dist = normalizePypi(n.name);
      const inst = installed.get(dist);
      const mods = inst?.modules ?? PYPI_MODULES[dist] ?? null;
      const guess = [dist.replace(/-/g, '_'), dist.replace(/[-.]/g, '_'), dist];
      const hitMod = [...(mods ?? []), ...guess].find((m) => imported.has(m));
      const hitWord = [...(mods ?? []), ...guess, ...(inst?.commands ?? [])].find((m) => tokens.has(m));
      const ev = hitMod ? imported.get(hitMod) : hitWord ? tokens.get(hitWord) : [];
      // Sure only with complete module names, no entry points (commands and plugins are loaded by name),
      // and not among the packages loaded by a name the project never writes.
      const sure = Boolean(mods) && !inst?.entryPoints && !PYPI_NEVER_ABSENT.has(dist);
      set(purl, ev.length > 0, ev, sure);
    }
  } else if (g.ecosystem === 'cargo') {
    const { imported, renames, outside, code } = await repo.cargo();
    if (!code) blocked = 'no Rust file in the repository';
    if (outside) blocked = outside;
    for (const [purl, n] of g.nodes) {
      // The library name is the package name with "-" as "_"; a few crates name it otherwise (md-5 → md5,
      // rust-ini → ini): those spellings are tried too.
      const names = [n.name.replace(/-/g, '_'), n.name.replace(/-/g, ''), n.name.replace(/^rust-/, '').replace(/-rs$/, '').replace(/-/g, '_'), ...(renames.get(n.name) ?? [])];
      const hit = names.find((x) => imported.has(x));
      set(purl, Boolean(hit), hit ? imported.get(hit) : [], true);
    }
  } else if (g.ecosystem === 'composer') {
    const { names, code } = await repo.composer();
    if (!code) blocked = 'no PHP file in the repository';
    const all = [...names.keys()];
    for (const [purl] of g.nodes) {
      const prefixes = g.autoload?.get(purl)?.prefixes ?? [];
      const hit = all.find((x) => prefixes.some((p) => x === p || x.startsWith(`${p}\\`) || x.startsWith(`${p}_`)));
      set(purl, Boolean(hit), hit ? names.get(hit) : [], prefixes.length > 0);
    }
  } else if (g.ecosystem === 'gem') {
    const { imported, bundlerRequire } = await repo.gem();
    for (const [purl, n] of g.nodes) {
      if (bundlerRequire && g.roots.has(purl)) { set(purl, true, [bundlerRequire], false); continue; }
      const cands = [n.name, n.name.replace(/-/g, '/'), n.name.replace(/-/g, '_')];
      const hit = [...imported.keys()].find((r) => cands.some((c) => r === c || r.startsWith(`${c}/`)));
      set(purl, Boolean(hit), hit ? imported.get(hit) : [], false);
    }
  } else if (g.ecosystem === 'nuget') {
    const { imported } = await repo.nuget();
    const names = [...imported.keys()];
    for (const [purl, n] of g.nodes) {
      const hit = names.find((x) => x === n.name || x.startsWith(`${n.name}.`));
      set(purl, Boolean(hit), hit ? imported.get(hit) : [], false);
    }
  }
  // Loaded whatever the code says.
  for (const [purl, why] of g.used) out.set(purl, { used: true, evidence: [{ file: '(lock file)', line: 0, how: why }], sure: true });
  for (const purl of g.unsure) { const u = out.get(purl); if (u) u.sure = false; }
  return { use: out, blocked };
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
const namesOf = (g, purls) => purls.map((c) => g.nodes.get(c)?.name ?? c);

/** The analysis of one lock file against the repository. Map purl → result, or null (no graph for this format). */
export async function analyseProject(lockPath, root, repo) {
  const g = await readGraph(lockPath);
  if (!g) return null;
  const { use, blocked } = await directUse(g, repo);
  const used = [...use].filter(([, u]) => u.used).map(([k]) => k);
  const unsure = [...use].filter(([, u]) => !u.used && !u.sure).map(([k]) => k);
  const fromUsed = walk(g, used);
  const fromExternal = walk(g, [...g.external]);
  const fromUnsure = walk(g, unsure);
  const fromRoots = walk(g, [...g.roots]);
  const project = relative(root, lockPath) || lockPath;
  const why = repo.incomplete ?? (repo.big.length ? `${repo.big.length} source file${repo.big.length > 1 ? 's' : ''} too large to read (${repo.big[0]})` : null) ?? blocked
    ?? (!g.complete ? 'the lock file does not give every dependency link' : null);
  const out = new Map();
  for (const purl of g.nodes.keys()) {
    const u = use.get(purl);
    if (u?.used) out.set(purl, { state: 'imported', evidence: u.evidence, project });
    else if (fromUsed.has(purl)) {
      const c = chainOf(fromUsed, purl);
      out.set(purl, { state: 'loaded', chain: namesOf(g, c), evidence: use.get(c[0])?.evidence ?? [], project });
    } else if (why) out.set(purl, { state: 'unknown', project, why });
    else if (fromExternal.has(purl)) out.set(purl, { state: 'unknown', project, why: 'it comes in through code outside the repository' });
    else if (fromUnsure.has(purl)) out.set(purl, { state: 'unknown', project, why: 'its import names, or those of what leads to it, are not sure' });
    else out.set(purl, { state: 'not_loaded', chain: namesOf(g, fromRoots.has(purl) ? chainOf(fromRoots, purl) : [purl]), project, ecosystem: g.ecosystem });
  }
  return out;
}

/**
 * Every lock file under root. Returns { components: Map purl → result (the most "used" answer across lock
 * files), projects, errors }. A component also listed in a lock file that could not be analysed (no
 * graph for its format, unreadable) is at best "unknown".
 */
export async function usage(root) {
  const locks = (await findLockFiles(root)).filter((f) => !/(?:^|\/)go\.mod$/.test(f));
  const repo = await repoUse(root);
  const components = new Map();
  const projects = [];
  const errors = [];
  const merge = (purl, r) => { const prev = components.get(purl); if (!prev || ORDER[r.state] > ORDER[prev.state]) components.set(purl, r); };
  for (const f of locks) {
    const rel = relative(root, f);
    let res = null;
    try { res = await analyseProject(f, root, repo); } catch (e) { errors.push({ file: rel, error: e.message }); }
    if (res) {
      projects.push(rel);
      for (const [purl, r] of res) merge(purl, r);
      continue;
    }
    // Not analysed: what it lists cannot be declared unused anywhere.
    try {
      for (const c of await readLockFile(f, root)) merge(c.purl, { state: 'unknown', project: rel, why: `${rel} could not be analysed` });
    } catch { /* unreadable: reported by the scan */ }
  }
  return { components, projects, errors };
}
