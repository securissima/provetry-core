// SPDX-License-Identifier: AGPL-3.0-only
// Reads the dependency lock files of a project and returns its components, with no third-party parser:
// every format is read by a small, tested function below. Nothing is executed and nothing is downloaded.
import { readdir, readFile, stat } from 'node:fs/promises';
import { basename, dirname, join, relative } from 'node:path';
import { makePurl, normalizePypi } from '../purl.js';
import { manifestDirectNames } from './manifests.js';
import { parseGradleLock, parsePomFile, POM_NOT_BUILD } from './java.js';

/**
 * @typedef {{ type: string, name: string, version: string, purl: string, scope?: 'required'|'optional'|'dev',
 *   direct?: boolean, hashes?: { alg: string, content: string }[], sources: string[] }} Component
 */

const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', 'vendor', 'dist', 'build', 'target', '.venv', 'venv', '__pycache__', '.next', '.astro', 'coverage']);
const MAX_FILE = 64 * 1024 * 1024;

/** One parser per file name. Each takes the text and returns components without `sources`. */
export const PARSERS = {
  'package-lock.json': parseNpmLock,
  'npm-shrinkwrap.json': parseNpmLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'yarn.lock': parseYarnLock,
  'requirements.txt': parseRequirements,
  'Pipfile.lock': parsePipfileLock,
  'poetry.lock': (t) => parseTomlPackages(t, 'pypi'),
  'uv.lock': (t) => parseTomlPackages(t, 'pypi'),
  'go.mod': parseGoMod,
  'Cargo.lock': (t) => parseTomlPackages(t, 'cargo'),
  'composer.lock': parseComposerLock,
  'Gemfile.lock': parseGemfileLock,
  'packages.lock.json': parseNugetLock,
  'gradle.lockfile': (t) => parseGradleLock(t),
  'buildscript-gradle.lockfile': (t) => parseGradleLock(t, { buildscript: true }),
  'pom.xml': null, // read with its parents: see readLockFile
};

/** Lists the lock files under `root` (not following symbolic links), up to `maxDepth` folders deep. */
export async function findLockFiles(root, maxDepth = 6) {
  const found = [];
  async function walk(dir, depth) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth && !SKIP_DIRS.has(e.name)) await walk(p, depth + 1);
      } else if (e.isFile() && (Object.hasOwn(PARSERS, e.name) || (/\.lockfile$/.test(e.name) && basename(dir) === 'dependency-locks'))) {
        // pom.xml of tests, templates or unpacked jars are not the product's build.
        if (e.name === 'pom.xml' && POM_NOT_BUILD.test(relative(root, p))) continue;
        found.push(p);
      }
    }
  }
  await walk(root, 0);
  return found.sort();
}

/** Reads one lock file. Throws a readable error for a file it cannot parse. */
export async function readLockFile(path, root = '.') {
  const s = await stat(path);
  if (s.size > MAX_FILE) throw new Error(`${path}: file too large (${s.size} bytes)`);
  const text = await readFile(path, 'utf8');
  const legacyGradle = /\.lockfile$/.test(path) && basename(dirname(path)) === 'dependency-locks';
  const parse = basename(path) === 'pom.xml' ? () => parsePomFile(path)
    : legacyGradle ? (t) => parseGradleLock(t, { configuration: basename(path, '.lockfile') }) : (Object.hasOwn(PARSERS, basename(path)) ? PARSERS[basename(path)] : null);
  if (!parse) throw new Error(`${path}: unknown lock file`);
  let comps;
  try {
    comps = await parse(text);
  } catch (e) {
    throw new Error(`${relative(root, path) || path}: cannot be read (${e.message})`);
  }
  const src = relative(root, path) || basename(path);
  // Lock files that do not say which dependencies are direct: ask the manifest next to them.
  if (!comps.some((c) => typeof c.direct === 'boolean')) {
    const names = await manifestDirectNames(dirname(path), basename(path));
    if (names) for (const c of comps) c.direct = names.has(c.type === 'pypi' ? normalizePypi(c.name) : c.name);
  }
  const out = comps.map((c) => ({ ...c, sources: [src] }));
  if (comps.notice) Object.defineProperty(out, 'notice', { value: { file: src, text: `${src} ${comps.notice.text}`, missing: comps.notice.missing }, enumerable: false });
  return out;
}

/** Merges components found in several files: one entry per purl, with every file it came from. */
export function mergeComponents(lists) {
  const byPurl = new Map();
  for (const c of lists.flat()) {
    const prev = byPurl.get(c.purl);
    if (!prev) {
      byPurl.set(c.purl, { ...c, sources: [...c.sources] });
      continue;
    }
    for (const s of c.sources) if (!prev.sources.includes(s)) prev.sources.push(s);
    // A component needed at run time anywhere is needed at run time.
    if (c.scope === 'required' || prev.scope === 'required') prev.scope = 'required';
    else if (c.scope === 'optional' || prev.scope === 'optional') prev.scope = 'optional';
    prev.direct = Boolean(prev.direct || c.direct);
    if (!prev.hashes?.length && c.hashes?.length) prev.hashes = c.hashes;
  }
  return [...byPurl.values()].sort((a, b) => a.purl.localeCompare(b.purl));
}

/** Finds and reads every lock file under `root`. Returns { components, files, errors }. */
export async function collect(root) {
  const files = await findLockFiles(root);
  const lists = [];
  const errors = [];
  const notices = [];
  for (const f of files) {
    try {
      const list = await readLockFile(f, root);
      if (list.notice) notices.push(list.notice);
      lists.push(list);
    } catch (e) {
      errors.push({ file: relative(root, f) || basename(f), error: e.message });
    }
  }
  return { components: mergeComponents(lists), files: files.map((f) => relative(root, f)), errors, notices };
}

const comp = (type, name, version, extra = {}) => ({ type, name, version, purl: makePurl(type, name, version), scope: 'required', ...extra });

/** npm integrity "sha512-<base64>" → { alg: 'SHA-512', content: hex } */
export function npmIntegrity(integrity) {
  const out = [];
  for (const part of String(integrity ?? '').split(/\s+/)) {
    const m = /^(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/=]+)$/.exec(part);
    if (!m) continue;
    const alg = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' }[m[1]];
    out.push({ alg, content: Buffer.from(m[2], 'base64').toString('hex') });
  }
  return out;
}

// ---------- npm ----------
export function parseNpmLock(text) {
  const lock = JSON.parse(text);
  const out = [];
  if (lock.packages && typeof lock.packages === 'object') {
    // lockfileVersion 2 and 3
    const root = lock.packages[''] ?? {};
    const directNames = new Set([...Object.keys(root.dependencies ?? {}), ...Object.keys(root.devDependencies ?? {}), ...Object.keys(root.optionalDependencies ?? {}), ...Object.keys(root.peerDependencies ?? {})]);
    for (const [key, p] of Object.entries(lock.packages)) {
      if (!key || p.link || !p.version) continue;
      // Workspace packages are listed by folder ("packages/foo"), without node_modules: they are the project, not dependencies.
      if (!key.includes('node_modules/')) continue;
      const name = p.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const topLevel = key.lastIndexOf('node_modules/') === key.indexOf('node_modules/') && key.startsWith('node_modules/');
      out.push(
        comp('npm', name, p.version, {
          scope: p.dev ? 'dev' : p.optional || p.devOptional ? 'optional' : 'required',
          direct: topLevel && directNames.has(name),
          hashes: npmIntegrity(p.integrity),
        }),
      );
    }
    return out;
  }
  // lockfileVersion 1: nested "dependencies"
  function walk(deps, top) {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (d.version && !/^(file|link):/.test(d.version)) {
        out.push(comp('npm', name, d.version, { scope: d.dev ? 'dev' : d.optional ? 'optional' : 'required', direct: top, hashes: npmIntegrity(d.integrity) }));
      }
      walk(d.dependencies, false);
    }
  }
  walk(lock.dependencies, true);
  return out;
}

/** Splits "@scope/name@1.2.3" or "name@1.2.3" into [name, version]. */
function splitAt(spec) {
  const i = spec.lastIndexOf('@');
  if (i <= 0) return [spec, ''];
  return [spec.slice(0, i), spec.slice(i + 1)];
}

// ---------- pnpm ----------
const pnpmVersion = (v) => String(v ?? '').replace(/^'|'$/g, '').replace(/\(.*$/, '').trim();
const pnpmKey = /^ {2}'?\/?((?:@[^/\s]+\/)?[^@\s'(]+)@([^:\s'(]+)(?:\([^)]*\))*'?:\s*(\{\})?\s*$/;

/** pnpm-lock.yaml, lockfile versions 6 and 9. */
export function parsePnpmLock(text) {
  const lines = text.split(/\r?\n/);
  const ver = /^lockfileVersion:\s*'?(\d+)/m.exec(text);
  if (ver && Number(ver[1]) < 6) throw new Error(`pnpm lockfile version ${ver[1]} is not supported (6 or later: run a recent pnpm install)`);
  const out = [];
  const byKey = new Map();
  // name@version → 'dev' | 'prod', for the dependencies each workspace project declares.
  const direct = new Map();
  // name@version → [name@version] it depends on, from "packages:" (v6) or "snapshots:" (v9).
  const graph = new Map();
  let top = null; // current top-level section
  let section = null; // 'dev' | 'prod' while inside a dependencies list
  let sectionIndent = -1;
  let entry = null;
  let current = null; // component being read in packages:
  let node = null; // graph node being read
  let nodeDeps = false;
  const note = (name, version, kind) => {
    const v = pnpmVersion(version);
    if (!v || /^(link|file|workspace):/.test(v)) return;
    const k = `${name}@${v}`;
    if (direct.get(k) !== 'prod') direct.set(k, kind);
  };
  let devFlags = false;
  for (const line of lines) {
    if (!line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    if (indent === 0) {
      top = line.replace(/:.*$/, '').trim();
      current = node = null;
      section = null;
      // Lockfile v6 for a single project: "dependencies:" and "devDependencies:" at the top level.
      if (/^(devDependencies|dependencies|optionalDependencies)$/.test(top)) {
        section = top === 'devDependencies' ? 'dev' : 'prod';
        sectionIndent = 0;
      }
      continue;
    }
    if (top === 'importers' || section) {
      const head = /^( *)(devDependencies|dependencies|optionalDependencies):\s*$/.exec(line);
      if (top === 'importers' && head) {
        section = head[2] === 'devDependencies' ? 'dev' : 'prod';
        sectionIndent = head[1].length;
        entry = null;
        continue;
      }
      if (!section || indent <= sectionIndent) {
        section = null;
        continue;
      }
      const m = /^ *'?(@?[^:'\s]+)'?:\s*(.*)$/.exec(line);
      if (!m) continue;
      if (indent === sectionIndent + 2) {
        if (m[2] && !m[2].startsWith('{')) note(m[1], m[2], section);
        entry = m[2] ? null : m[1];
      } else if (entry && m[1] === 'version') note(entry, m[2], section);
      continue;
    }
    if (top === 'packages' || top === 'snapshots') {
      const key = pnpmKey.exec(line);
      if (key) {
        const k = `${key[1]}@${key[2]}`;
        node = graph.get(k) ?? [];
        graph.set(k, node);
        nodeDeps = false;
        current = null;
        if (top === 'packages' && !byKey.has(k)) {
          current = comp('npm', key[1], key[2]);
          byKey.set(k, current);
          out.push(current);
        }
        continue;
      }
      if (indent === 4) nodeDeps = /^ {4}(dependencies|optionalDependencies):\s*$/.test(line);
      else if (indent === 6 && nodeDeps && node) {
        const d = /^ {6}'?(@?[^:'\s]+)'?:\s*'?([^'\s]+)/.exec(line);
        if (d) node.push(`${d[1]}@${pnpmVersion(d[2])}`);
      }
      if (current) {
        if (/^ {4}dev: true/.test(line)) {
          current.scope = 'dev';
          devFlags = true;
        } else if (/^ {4}dev: false/.test(line)) devFlags = true;
        else if (/^ {4}optional: true/.test(line) && current.scope !== 'dev') current.scope = 'optional';
        const integ = /^ {4}resolution: \{integrity: ([^,}]+)/.exec(line);
        if (integ) current.hashes = npmIntegrity(integ[1].trim());
      }
    }
  }
  if (direct.size) {
    for (const c of out) c.direct = direct.has(`${c.name}@${c.version}`);
    // Lockfile v9 no longer flags development packages: work it out from the graph. What the run-time
    // dependencies reach is required; what only development dependencies reach is development only.
    if (!devFlags && graph.size) {
      const reach = (roots) => {
        const seen = new Set();
        const stack = [...roots];
        while (stack.length) {
          const k = stack.pop();
          if (seen.has(k)) continue;
          seen.add(k);
          for (const d of graph.get(k) ?? []) stack.push(d);
        }
        return seen;
      };
      const prod = reach([...direct].filter(([, kind]) => kind === 'prod').map(([k]) => k));
      const dev = reach([...direct].filter(([, kind]) => kind === 'dev').map(([k]) => k));
      for (const c of out) {
        const k = `${c.name}@${c.version}`;
        if (!prod.has(k) && dev.has(k) && c.scope !== 'optional') c.scope = 'dev';
      }
    } else {
      for (const c of out) if (direct.get(`${c.name}@${c.version}`) === 'dev' && c.scope === 'required') c.scope = 'dev';
    }
  }
  return dedupe(out);
}

// ---------- yarn (v1 and Berry) ----------
export function parseYarnLock(text) {
  const out = [];
  const blocks = text.split(/\r?\n(?=\S)/);
  for (const block of blocks) {
    const lines = block.split(/\r?\n/);
    const head = lines[0].trim();
    if (!head || head.startsWith('#') || head.startsWith('__metadata')) continue;
    const first = head.replace(/:$/, '').split(',')[0].trim().replace(/^"|"$/g, '');
    // The descriptor is "name@range"; the name may be scoped ("@scope/name"), the range may hold another "@".
    const at = first.indexOf('@', 1);
    let [name, range] = at > 0 ? [first.slice(0, at), first.slice(at + 1)] : [first, ''];
    if (/^(workspace|link|portal|file|patch):/.test(range) || range.includes('@workspace:')) continue;
    if (range.startsWith('npm:')) {
      const alias = range.slice(4);
      // "alias@npm:real-name@^1" → the real package
      const aliasAt = alias.indexOf('@', 1);
      if (aliasAt > 0 && !/^[\^~<>=\d*]/.test(alias)) name = alias.slice(0, aliasAt);
    }
    const v = lines.map((l) => /^ {2}version:? "?([^"\s]+)"?/.exec(l)).find(Boolean);
    if (!v) continue;
    const integ = lines.map((l) => /^ {2}integrity:? "?([^"\s]+)"?/.exec(l)).find(Boolean);
    out.push(comp('npm', name, v[1], { hashes: integ ? npmIntegrity(integ[1]) : [] }));
  }
  return dedupe(out);
}

// ---------- Python ----------
export function parseRequirements(text) {
  const out = [];
  // Join continuation lines ("pkg==1.0 \\\n    --hash=sha256:…"), keeping pip-compile's "# via" comments apart.
  const lines = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  const annotated = lines.some((l) => /^\s*#\s+via\b/.test(l) || /\s#\s+via\b/.test(l));
  let last = null;
  const viaDirect = (text) => /-r\s|-c\s|\.in\b|pyproject\.toml|setup\.(py|cfg)/.test(text);
  for (const raw of lines) {
    // A comment line: pip-compile's "# via …" block belongs to the package above it.
    if (/^\s*#/.test(raw)) {
      const via = /^\s*#\s+(?:via\b)?(.*)$/.exec(raw);
      if (last && via && (/#\s+via\b/.test(raw) || /^\s+#\s+(-r|-c)\s/.test(raw)) && viaDirect(via[1])) last.direct = true;
      continue;
    }
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('-')) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+!-]+)/.exec(line);
    last = null;
    if (!m) continue; // only pinned versions can be matched against vulnerabilities
    const hashes = [...line.matchAll(/--hash[= ](sha256):([0-9a-f]{64})/g)].map((h) => ({ alg: 'SHA-256', content: h[2] }));
    last = comp('pypi', m[1], m[2], { hashes, ...(annotated ? { direct: false } : {}) });
    // Inline form: "flask==2.0.1  # via -r requirements.in"
    const inline = /\s#\s+via\b(.*)$/.exec(raw);
    if (inline && viaDirect(inline[1])) last.direct = true;
    out.push(last);
  }
  return out;
}

export function parsePipfileLock(text) {
  const lock = JSON.parse(text);
  const out = [];
  for (const [section, scope] of [['default', 'required'], ['develop', 'dev']]) {
    for (const [name, p] of Object.entries(lock[section] ?? {})) {
      const v = String(p.version ?? '').replace(/^==/, '');
      if (!v) continue;
      const hashes = (p.hashes ?? []).map((h) => /^sha256:([0-9a-f]{64})$/.exec(h)).filter(Boolean).map((m) => ({ alg: 'SHA-256', content: m[1] }));
      out.push(comp('pypi', name, v, { scope, hashes }));
    }
  }
  return out;
}

/** poetry.lock, uv.lock and Cargo.lock: [[package]] tables with name = "...", version = "...". */
export function parseTomlPackages(text, type) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[(?!\[package)/m)[0].split(/^\[\[(?!package\]\])/m)[0];
    const get = (k) => new RegExp(`^${k}\\s*=\\s*"([^"]*)"`, 'm').exec(body)?.[1];
    const name = get('name');
    const version = get('version');
    if (!name || !version) continue;
    if (type === 'cargo' && !/^source\s*=/m.test(body)) continue; // workspace members, not dependencies
    if (type === 'pypi' && /^source\s*=\s*\{\s*(virtual|editable)\s*=/m.test(body)) continue; // the project itself (uv)
    const category = get('category');
    const optional = /^optional\s*=\s*true/m.test(body);
    out.push(comp(type, name, version, { scope: category === 'dev' ? 'dev' : optional ? 'optional' : 'required' }));
  }
  return out;
}

// ---------- Go ----------
export function parseGoMod(text) {
  const out = [];
  const stripped = text.replace(/\/\*[\s\S]*?\*\//g, '');
  const add = (line) => {
    const m = /^\s*([^\s]+)\s+(v[^\s]+)(\s*\/\/\s*indirect)?/.exec(line);
    if (m) out.push(comp('golang', m[1], m[2], { direct: !m[3] }));
  };
  for (const block of stripped.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) for (const line of block[1].split(/\r?\n/)) add(line);
  for (const single of stripped.matchAll(/^require\s+([^\s(][^\n]*)$/gm)) add(single[1]);
  // A replace directive points the module at another one: report the replacement, which is what is built.
  // "old => new vX" swaps the module; "old vA => …" only that version; "old => ../local" a local copy (not a
  // published module, so nothing to look up: it is left out).
  const repl = [];
  const addRepl = (line) => {
    const m = /^\s*([^\s]+)(?:\s+(v[^\s]+))?\s*=>\s*([^\s]+)(?:\s+(v[^\s]+))?/.exec(line);
    if (m) repl.push({ from: m[1], fromVersion: m[2] ?? null, to: m[3], toVersion: m[4] ?? null });
  };
  for (const block of stripped.matchAll(/^replace\s*\(([\s\S]*?)^\)/gm)) for (const line of block[1].split(/\r?\n/)) addRepl(line);
  for (const single of stripped.matchAll(/^replace\s+([^\s(][^\n]*)$/gm)) addRepl(single[1]);
  const result = [];
  for (const c of out) {
    const r = repl.find((x) => x.from === c.name && (!x.fromVersion || x.fromVersion === c.version));
    if (!r) result.push(c);
    else if (r.toVersion) result.push(comp('golang', r.to, r.toVersion, { direct: c.direct }));
  }
  // The Go toolchain is a component too: its standard library has advisories of its own. Only the "toolchain"
  // directive names the version that builds the module; the "go" line is a minimum, so it is not used.
  const tc = /^toolchain\s+go(\d+\.\d+\.\d+)\s*$/m.exec(stripped);
  if (tc) result.push(comp('golang', 'stdlib', `v${tc[1]}`, { direct: true }));
  return result;
}

// ---------- PHP ----------
export function parseComposerLock(text) {
  const lock = JSON.parse(text);
  const out = [];
  for (const [key, scope] of [['packages', 'required'], ['packages-dev', 'dev']]) {
    for (const p of lock[key] ?? []) {
      if (!p.name || !p.version || /^dev-/.test(p.version)) continue;
      const hashes = p.dist?.shasum ? [{ alg: 'SHA-1', content: p.dist.shasum }] : [];
      out.push(comp('composer', p.name, p.version.replace(/^v(?=\d)/, ''), { scope, hashes }));
    }
  }
  return out;
}

// ---------- Ruby ----------
export function parseGemfileLock(text) {
  const out = [];
  let inGem = false;
  let inSpecs = false;
  let inDeps = false;
  const directNames = new Set();
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inGem = line.trim() === 'GEM';
      inDeps = line.trim() === 'DEPENDENCIES';
      inSpecs = false;
      continue;
    }
    if (inDeps) {
      const d = /^ {2}([A-Za-z0-9._-]+)/.exec(line);
      if (d) directNames.add(d[1]);
      continue;
    }
    if (inGem && /^ {2}specs:\s*$/.test(line)) {
      inSpecs = true;
      continue;
    }
    if (!inGem || !inSpecs) continue;
    const m = /^ {4}([A-Za-z0-9._-]+) \(([^)]+)\)\s*$/.exec(line);
    if (m) out.push(comp('gem', m[1], m[2].replace(/-(x86|x64|arm|aarch|java|universal|mingw|mswin|darwin|linux)[\w.-]*$/, '')));
  }
  if (directNames.size) for (const c of out) c.direct = directNames.has(c.name);
  return dedupe(out);
}

// ---------- .NET ----------
export function parseNugetLock(text) {
  const lock = JSON.parse(text);
  const out = [];
  for (const deps of Object.values(lock.dependencies ?? {})) {
    for (const [name, d] of Object.entries(deps ?? {})) {
      if (d.type === 'Project' || !d.resolved) continue;
      const hashes = d.contentHash ? [{ alg: 'SHA-512', content: Buffer.from(d.contentHash, 'base64').toString('hex') }] : [];
      out.push(comp('nuget', name, d.resolved, { direct: d.type === 'Direct', hashes }));
    }
  }
  return dedupe(out);
}

function dedupe(list) {
  const seen = new Map();
  for (const c of list) {
    const prev = seen.get(c.purl);
    if (!prev) seen.set(c.purl, c);
    else if (c.scope === 'required') prev.scope = 'required';
  }
  return [...seen.values()];
}
