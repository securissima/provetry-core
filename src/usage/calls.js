// Call analysis on top of the function names (functions.js): where a name of the package is mentioned,
// look for a call of the package's own function, through the aliases and the paths the code takes.
//
// It only ever adds evidence of a call ("called", with the file and line). It never takes a mention
// away: the call analyses miss calls (a function passed as a callback to native code, re-exports, a
// module copied with a spread…), so "no call found" says nothing, and the finding keeps "mentioned".
//
// JavaScript and TypeScript: Jelly (Aarhus University, BSD-3-Clause), run with npx at a fixed version,
// or from PROVETRY_JELLY (the path of its jelly.js). Python: the imports and the calls of each file,
// read here (from M import f as g; g(…) / import M as m; m.sub.f(…)).
import { execFile } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectFiles, readText, PYPI_MODULES } from './imports.js';
import { normalizePypi } from '../purl.js';

export const JELLY = '@cs-au-dk/jelly@0.13.0';
const NAME = /^[A-Za-z_$][\w$]*$/;
const PKG = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i;

// The child gets no secret of the pipeline (the Provetry API key, tokens…), and keeps the Node options
// a CI may need (certificates).
const SECRET = /KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH/i;
function childEnv() {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !SECRET.test(k)));
  env.NODE_OPTIONS = [process.env.NODE_OPTIONS, '--max-old-space-size=4096'].filter(Boolean).join(' ');
  return env;
}

function run(cmd, args, { cwd, timeout }) {
  return new Promise((done) => {
    execFile(cmd, args, { cwd, timeout, maxBuffer: 64 * 1024 * 1024, env: childEnv() }, (error, stdout, stderr) => done({ error, stdout, stderr }));
  });
}

/** Jelly from Provetry's own install, when it is there. */
function ownJelly() {
  try { return fileURLToPath(import.meta.resolve('@cs-au-dk/jelly/lib/main.js')); } catch { return null; }
}

/** The narrowest place of a Jelly match ("file:l1:c1:l2:c2"): the call itself, not its enclosing function. */
export function narrowest(locs, root) {
  let best = null;
  for (const loc of locs ?? []) {
    const m = /^(.*):(\d+):(\d+):(\d+):(\d+)$/.exec(String(loc));
    if (!m) continue;
    const abs = isAbsolute(m[1]) ? m[1] : resolve(root, m[1]);
    const file = relative(resolve(root), abs);
    if (!file || file.startsWith('..') || /(?:^|\/)node_modules\//.test(file)) continue;
    const span = (Number(m[4]) - Number(m[2])) * 1e6 + (Number(m[5]) - Number(m[3]));
    if (!best || span < best.span) best = { file: file.split('\\').join('/'), line: Number(m[2]), span };
  }
  return best && { file: best.file, line: best.line };
}

/**
 * The Jelly pattern of one finding: a call of one of the names, read directly on the package or one of its
 * modules. Not deeper (no "**"): a method of the same name on what the package returns or creates is
 * another function.
 */
export function jellyPattern(pkg, names) {
  if (!PKG.test(pkg) || !names.length || !names.every((n) => NAME.test(n))) return null;
  const props = names.length === 1 ? names[0] : `{${names.join(',')}}`;
  return `call {<${pkg}>,<${pkg}/**>}.${props}`;
}

/**
 * npm: { key → { file, line, name } } for the findings whose function Jelly sees called.
 * items: [{ key, pkg, names }]. Any failure (no npx, no network, a timeout): an empty map.
 */
export async function jellyCalls(root, items, { timeout = 300_000, jelly = process.env.PROVETRY_JELLY ? resolve(process.env.PROVETRY_JELLY) : ownJelly() } = {}) {
  const out = new Map();
  const vulns = [];
  const byId = new Map();
  // One pattern per name: the match then says which function is called.
  items.forEach((it, i) => it.names.forEach((n, j) => {
    const pattern = jellyPattern(it.pkg, [n]);
    if (!pattern) return;
    const id = `PROVETRY-${i}-${j}`;
    byId.set(id, { ...it, name: n });
    vulns.push({ osv: { id, affected: [{ package: { name: it.pkg }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }] }] }, patterns: [pattern] });
  }));
  if (!vulns.length) return out;
  const dir = await mkdtemp(join(tmpdir(), 'provetry-jelly-'));
  try {
    await writeFile(join(dir, 'v.json'), JSON.stringify(vulns));
    const args = ['-i', String(Math.floor(timeout / 1000) - 10), '--ignore-dependencies', '--vulnerabilities', join(dir, 'v.json'), '--matches-file', join(dir, 'm.json'), '-b', resolve(root), resolve(root)];
    // From a folder of its own: the repository's .npmrc, package.json or node_modules must not decide what
    // npx fetches or runs.
    const r = jelly ? await run(process.execPath, [jelly, ...args], { cwd: dir, timeout })
      : await run(process.platform === 'win32' ? 'npx.cmd' : 'npx', ['--yes', JELLY, ...args], { cwd: dir, timeout });
    if (r.error) return out;
    let matches;
    try { matches = JSON.parse(await readFile(join(dir, 'm.json'), 'utf8')); } catch { return out; }
    for (const [id, locs] of Object.entries(matches ?? {})) {
      const it = byId.get(id);
      const at = it && narrowest(locs, root);
      const prev = it && out.get(it.key);
      if (at && (!prev || prev.file > at.file || (prev.file === at.file && prev.line > at.line))) out.set(it.key, { ...at, names: [it.name] });
    }
    return out;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** Python source without strings and comments (same length, line breaks kept). */
export function blankPy(src) {
  return src.replace(/("""|''')[\s\S]*?\1|(['"])(?:\\.|(?!\2)[^\\\n])*\2|#[^\n]*/g, (m) => m.replace(/[^\n]/g, ' '));
}

const words = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);

/**
 * Python: the first call of one of `names` from one of the `modules` in a file's source, or null.
 * Counts:  from M[.x] import f [as g] … g(…) ;  import M[.x] [as m] … m[.x].f(…) / M.x.f(…).
 * A name the file binds again (def, class, assignment, for, with … as, another import) does not count.
 */
export function pyCall(src, modules, names) {
  const text = blankPy(src).replace(/\\\n/g, '  ');
  const lines = text.split('\n');
  const isMod = (m) => modules.some((x) => m === x || m.startsWith(`${x}.`));
  // Statements in parentheses on one line (same length: positions stay where they are).
  const flat = text.replace(/\(([^()]*)\)/g, (m, inner) => `(${inner.replace(/\n/g, ' ')})`);
  const fnAlias = new Map(); // local name → function name
  const modPath = new Map(); // how the code writes a module of the package (yaml, yaml.composer, y) → the name it binds
  const importLines = new Set();
  const own = flat.split(''); // UTF-16 units, as the match positions count them
  const blank = (start, end) => { for (let i = start; i < end; i++) if (own[i] !== '\n') own[i] = ' '; };
  for (const m of flat.matchAll(/^[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+\(?([^)\n]*)\)?/gm)) {
    if (!isMod(m[1])) continue;
    importLines.add(text.slice(0, m.index).split('\n').length);
    blank(m.index, m.index + m[0].length);
    for (const w of words(m[2])) {
      const [n, , as] = w.split(/\s+/);
      if (n === '*') return null; // every name of the module: whose is whose is not known here
      if (names.includes(n)) fnAlias.set(as ?? n, n);
      // Anything else imported this way (a submodule, a class) is left out: its methods may share a name.
    }
  }
  for (const m of text.matchAll(/^[ \t]*import[ \t]+([^\n;]+)/gm)) {
    let ours = false;
    for (const w of words(m[1])) {
      const [mod, , as] = w.split(/\s+/);
      if (!isMod(mod)) continue;
      ours = true;
      // import a.b.c binds a; the call must then go through the whole path (a.b is not the package).
      modPath.set(as ?? mod, as ?? mod.split('.')[0]);
    }
    if (ours) { importLines.add(text.slice(0, m.index).split('\n').length); blank(m.index, m.index + m[0].length); }
  }
  const ownText = own.join('');
  const L = (n) => n.replace(/\./g, '\\.');
  // Bound again anywhere in the file: def, class, assignment (plain, annotated, augmented, walrus), for,
  // with/except … as, global, lambda or function parameter, match … case, or an import from elsewhere.
  const rebound = (local) => new RegExp([
    `^[ \\t]*(?:(?:async[ \\t]+)?def|class)[ \\t]+${local}\\b`,
    `^[ \\t]*(?:[\\w.,\\s*]*,[ \\t]*)?\\*?${local}[ \\t]*(?:,[^=\\n]*)?(?:[-+*/%&|^@]|\\*\\*|//|>>|<<)?=(?!=)`,
    `^[ \\t]*${local}[ \\t]*:(?!=)`,
    `(?<![\\w.])${local}[ \\t]*:=`,
    `\\bfor[ \\t]+[^\\n]*?(?<![\\w.])${local}\\b[^\\n]*\\bin\\b`,
    `\\bas[ \\t]+${local}\\b`,
    `\\bglobal[ \\t]+[^\\n]*\\b${local}\\b`,
    `\\blambda\\b[^:\\n]*\\b${local}\\b`,
    `\\bdef[ \\t]+\\w+[ \\t]*\\([^)]*\\b${local}\\b`,
    `^[ \\t]*case\\b[^\\n]*(?<![\\w.])${local}\\b`,
    `^[ \\t]*(?:from[ \\t]+\\S+[ \\t]+)?import[ \\t][^\\n]*(?<![\\w.])${local}\\b`,
  ].join('|'), 'm');
  const live = (local) => !rebound(local).test(ownText);
  const calls = [];
  for (const [local, fn] of fnAlias) if (live(local)) calls.push([new RegExp(`(?<![\\w.])${local}[ \\t]*\\(`), fn]);
  for (const [path, local] of modPath) {
    if (!live(local)) continue;
    for (const fn of names) calls.push([new RegExp(`(?<![\\w.])${L(path)}[ \\t]*\\.[ \\t]*${fn}[ \\t]*\\(`), fn]);
  }
  let best = null;
  for (const [re, fn] of calls) {
    for (let i = 0; i < lines.length; i++) {
      if (importLines.has(i + 1)) continue;
      if (re.test(lines[i])) { if (!best || i + 1 < best.line) best = { line: i + 1, name: fn }; break; }
    }
  }
  return best;
}

/** The import names of a PyPI distribution: the known ones, else the usual spellings of its name. */
export function pyModules(name) {
  const dist = normalizePypi(name);
  return [...new Set([...(PYPI_MODULES[dist] ?? []), dist.replace(/-/g, '_'), dist.replace(/[-.]/g, '_')])];
}

/** PyPI: { key → { file, line, name } } for the findings whose function is called in a file of the project. */
export async function pythonCalls(root, items) {
  const out = new Map();
  if (!items.length) return out;
  const { files, incomplete } = await projectFiles(root);
  if (incomplete) return out;
  for (const f of files.filter((x) => /\.py$/.test(x))) {
    const src = await readText(root, f);
    if (src == null) continue;
    for (const it of items) {
      if (out.has(it.key) || !it.names.every((n) => /^[A-Za-z_]\w*$/.test(n))) continue;
      const hit = pyCall(src, pyModules(it.pkg), it.names);
      if (hit) out.set(it.key, { file: f, line: hit.line, names: [hit.name] });
    }
  }
  return out;
}

/**
 * Adds `called: { file, line, by }` to the "mentioned" results of `functions` (packageFunctions)
 * that a call analysis confirms. `findings` as for packageFunctions; `data` the same records.
 */
export async function confirmCalls(root, findings, functions, data, { jelly = true, timeout } = {}) {
  const npm = [];
  const py = [];
  for (const f of findings) {
    const key = `${f.id}|${f.component.purl}`;
    const fn = functions.get(key);
    const rec = data.get(key);
    if (fn?.result !== 'mentioned' || !rec) continue;
    const names = (rec.entryPoints ?? []).filter((n) => !n.startsWith('module:'));
    if (!names.length) continue;
    if (f.component.type === 'npm') npm.push({ key, pkg: f.component.name, names });
    else if (f.component.type === 'pypi') py.push({ key, pkg: f.component.name, names });
  }
  const found = new Map([...(jelly && npm.length ? [...(await jellyCalls(root, npm, { timeout }))].map(([k, v]) => [k, { ...v, by: 'Jelly call graph' }]) : []),
    ...[...(await pythonCalls(root, py))].map(([k, v]) => [k, { ...v, by: 'Python import and call reading' }])]);
  for (const [k, v] of found) functions.set(k, { ...functions.get(k), called: { file: v.file, line: v.line, name: v.names[0], by: v.by } });
  return found.size;
}
