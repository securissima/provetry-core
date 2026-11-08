// SPDX-License-Identifier: AGPL-3.0-only
// What the project's own files use, read from the whole repository (nothing is executed): for each
// language, the names imported in code, and the names written anywhere else (configurations, scripts,
// Dockerfiles, CI files). Reading the whole repository rather than the folder of each lock file errs on the
// side of "used": the dangerous mistake is to call something unused.
import { readdir, readFile, stat, realpath, access } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

// Never the project's own code: dependencies, tool caches, generated output of frameworks.
const SKIP = new Set(['node_modules', '.git', '.hg', '.svn', '__pycache__', '.next', '.nuxt', '.astro', '.svelte-kit', '.tox', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.gradle', '.idea', '.vscode']);
const MAX_FILE = 8 * 1024 * 1024;
const MAX_FILES = 200_000;
const exists = (p) => access(p).then(() => true, () => false);

/** A folder that only holds installed dependencies or build output, recognised by what is in it. */
async function isDependencyFolder(p, name) {
  if (await exists(join(p, 'pyvenv.cfg'))) return true; // a Python virtual environment
  if (name === 'vendor' && ((await exists(join(p, 'autoload.php'))) || (await exists(join(p, 'modules.txt'))) || (await exists(join(p, 'bundle'))))) return true; // Composer, Go, Bundler
  if (name === 'target' && (await exists(join(p, 'CACHEDIR.TAG')))) return true; // Cargo
  return false;
}

/**
 * The project's files under root. `incomplete` when some could not be read (too many files, a symbolic
 * link to a folder outside the repository): conclusions of absence are not drawn then.
 */
export async function projectFiles(root) {
  const files = [];
  let incomplete = null;
  const realRoot = await realpath(root);
  async function walk(d) {
    let entries;
    try { entries = await readdir(d, { withFileTypes: true }); } catch { incomplete ??= `${relative(root, d) || '.'} could not be read`; return; }
    for (const e of entries) {
      if (files.length >= MAX_FILES) { incomplete ??= `more than ${MAX_FILES} files`; return; }
      const p = join(d, e.name);
      if (e.isSymbolicLink()) {
        try {
          const target = await realpath(p);
          if (target !== realRoot && !target.startsWith(realRoot + sep)) incomplete ??= `${relative(root, p)} links outside the repository`;
        } catch { /* dangling link */ }
        continue; // inside the repository: read where it really is
      }
      if (e.isDirectory()) { if (!SKIP.has(e.name) && !(await isDependencyFolder(p, e.name))) await walk(p); }
      else if (e.isFile()) files.push(relative(root, p));
    }
  }
  await walk(root);
  return { files: files.sort(), incomplete };
}

/** Reads a file; null when too large (listed in `big`, so that the caller can draw no conclusion). */
export async function readText(root, f, big) {
  try {
    const s = await stat(join(root, f));
    if (s.size > MAX_FILE) { big?.push(f); return null; }
    return await readFile(join(root, f), 'utf8');
  } catch { return null; }
}

/** Records where a name is used: a few files per name are enough as evidence. `line` may be a function. */
function add(map, name, file, line, how) {
  const list = map.get(name) ?? map.set(name, []).get(name);
  if (list.length < 5 && !list.some((x) => x.file === file)) list.push({ file, line: typeof line === 'function' ? line() : line, how });
}
/** Line numbers of a text, by binary search over its line starts (computed once, when first needed). */
function liner(src) {
  let starts = null;
  return (index) => () => {
    if (!starts) { starts = [0]; for (let i = src.indexOf('\n'); i >= 0; i = src.indexOf('\n', i + 1)) starts.push(i + 1); }
    let lo = 0; let hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= index) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
}

/** Files that name tools and packages in plain words: build, deployment and CI files, shell scripts. */
export const OPS = /(?:^|\/)(?:Dockerfile[^/]*|Containerfile|[^/]*\.dockerfile|Makefile|GNUmakefile|Procfile[^/]*|Justfile|[^/]*\.(?:sh|bash|zsh|ya?ml|env|ini|cfg|conf)|\.env[^/]*)$/;
const PY_MANIFEST = /(?:^|\/)(?:pyproject\.toml|setup\.cfg|tox\.ini)$/;
/** A Python manifest without its dependency lists (which name every dependency, and are not a use). */
export function withoutDependencyLists(text) {
  const out = [];
  let section = '';
  let skipping = false;
  for (const line of String(text).split(/\r?\n/)) {
    const h = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (h) { section = h[1]; skipping = false; out.push(line); continue; }
    if (/dependencies|requires|extras|dependency-groups/i.test(section)) continue;
    if (skipping) { if (/^\S/.test(line) && !/^\s*\]/.test(line)) skipping = false; else { if (/^\s*\]/.test(line)) skipping = false; continue; } }
    if (/^\s*(?:dependencies|optional-dependencies|install_requires|setup_requires|tests_require|extras_require|requires|deps|build-backend-requires)\s*[=:]/i.test(line)) { skipping = !/\]\s*$/.test(line) && (/\[\s*$/.test(line) || /[=:]\s*$/.test(line) || /\[[^\]]*$/.test(line)); continue; }
    out.push(line);
  }
  return out.join('\n');
}
const LOCKS = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|poetry\.lock|uv\.lock|Pipfile(?:\.lock)?|composer\.lock|Gemfile(?:\.lock)?|packages\.lock\.json|go\.(?:mod|sum)|requirements[^/]*\.(?:txt|in)|constraints[^/]*\.txt|pyproject\.toml|setup\.cfg|tox\.ini|Cargo\.toml|composer\.json)$/;

/** Every word of a text (names of tools, packages, modules): word → evidence. */
function words(map, src, f, how, { dotted = false } = {}) {
  const L = liner(src);
  const seen = new Set();
  for (const m of src.matchAll(/[@A-Za-z0-9_][@A-Za-z0-9_./+-]*/g)) {
    const w = m[0].replace(/[./:+-]+$/, '');
    if (w.length < 2 || w.length > 214) continue;
    // "django_redis.cache.RedisCache", "mysql+pymysql": every part and dotted prefix is a name too.
    const all = [w];
    if (dotted) for (const part of w.split(/[+/]/)) { const d = part.split('.'); for (let i = 1; i <= d.length; i++) all.push(d.slice(0, i).join('.')); }
    for (const x of all) { if (!x || seen.has(x)) continue; seen.add(x); add(map, x, f, L(m.index), how); }
  }
}

// ---------- JavaScript / TypeScript ----------
const NODE_BUILTINS = new Set(['assert', 'buffer', 'child_process', 'cluster', 'console', 'constants', 'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https', 'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib', 'async_hooks', 'diagnostics_channel', 'inspector', 'trace_events', 'test']);
/** "lodash/fp" → "lodash", "@scope/pkg/x" → "@scope/pkg"; null for relative paths and built-ins. */
export function npmPackageOf(spec) {
  if (!spec) return null;
  const s = String(spec).replace(/^~/, '').replace(/^(?:\.{0,2}\/)*node_modules\//, '');
  if (/^[./#]/.test(s) || (/^[a-z]+:/i.test(s) && !s.startsWith('@'))) return null;
  const parts = s.split('/');
  const name = s.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  if (!/^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(name) || NODE_BUILTINS.has(name)) return null;
  return name;
}
const JS_CODE = /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/;
const JS_TEXT = /\.(?:json|toml|css|scss|sass|less|styl|html?|mdx|xml)$/;
const JS_CONFIG = /(?:^|\/)(?:[^/]+\.config\.[cm]?[jt]s|\.[^/]+rc\.[cm]?[jt]s|\.[A-Za-z0-9_-]+rc)$/;
const JS_IMPORT = /\b(?:import|export)\s+(?:type\s+)?(?:[^'"`;]*?\s+from\s+)?['"]([^'"\n]+)['"]|\b(?:require|import|require\.resolve)\s*\(\s*['"`]([^'"`\n]+)['"`]\s*\)/g;
const QUOTED = /['"`(]([^'"`()\s]{1,240})['"`)]/g;

/**
 * npm: `import`/`require` in the code; any package named in a string of the project's files (configs
 * that load plugins by name, style sheets); any word of the configuration, script, build and CI files
 * (`npx prisma`, `node -r dotenv/config`, `plugins: { autoprefixer: {} }`).
 */
export async function jsUse(root, files, big) {
  const imported = new Map();
  const named = new Map();
  const tokens = new Map();
  let code = 0;
  for (const f of files) {
    if (LOCKS.test(f)) continue;
    const isCode = JS_CODE.test(f);
    const isPkg = /(?:^|\/)package\.json$/.test(f);
    const isOps = OPS.test(f) || JS_CONFIG.test(f);
    if (!isCode && !isPkg && !isOps && !JS_TEXT.test(f)) continue;
    let src = await readText(root, f, isCode ? big : null);
    if (src == null) continue;
    let L = liner(src);
    if (isCode) code++;
    if (isPkg) {
      // The dependency lists name every dependency: they are not a use. Scripts and settings are.
      try {
        const pj = JSON.parse(src);
        for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies', 'overrides', 'resolutions', 'peerDependenciesMeta', 'dependenciesMeta', 'name', 'workspaces', 'pnpm']) delete pj[k];
        for (const v of Object.values(pj.scripts ?? {})) words(tokens, String(v), f, 'run by a script');
        src = JSON.stringify(pj, null, 1);
        L = liner(src);
      } catch { /* not JSON: read as text */ }
    }
    if (isCode) for (const m of src.matchAll(JS_IMPORT)) { const p = npmPackageOf(m[1] ?? m[2]); if (p) add(imported, p, f, L(m.index), 'imported'); }
    for (const m of src.matchAll(QUOTED)) { const p = npmPackageOf(m[1]); if (p) add(named, p, f, L(m.index), 'named'); }
    if (isOps) words(tokens, src, f, 'named');
  }
  return { imported, named, tokens, code };
}

// ---------- Python ----------
/**
 * Distribution name → the modules it installs, when they differ from the name and the list is complete.
 * Anything not here, and not found in an installed environment, is "not sure": no absence concluded.
 */
export const PYPI_MODULES = {
  beautifulsoup4: ['bs4'], pyyaml: ['yaml'], pillow: ['PIL'], 'scikit-learn': ['sklearn'], 'python-dateutil': ['dateutil'],
  'opencv-python': ['cv2'], 'opencv-python-headless': ['cv2'], protobuf: ['google.protobuf'], attrs: ['attr', 'attrs'], pyjwt: ['jwt'],
  'python-dotenv': ['dotenv'], pycryptodome: ['Crypto'], pycryptodomex: ['Cryptodome'], pyopenssl: ['OpenSSL'],
  'typing-extensions': ['typing_extensions'], 'python-jose': ['jose'], 'python-magic': ['magic'], dnspython: ['dns'], pyzmq: ['zmq'],
  'scikit-image': ['skimage'], 'importlib-metadata': ['importlib_metadata'], 'importlib-resources': ['importlib_resources'],
  'charset-normalizer': ['charset_normalizer'], 'websocket-client': ['websocket'], grpcio: ['grpc'], 'markdown-it-py': ['markdown_it'],
};
/**
 * Loaded by a name that the project never writes, or present at every start: database drivers chosen by a
 * URL or a setting, servers and workers started from the command line, the packaging tools. Never "not loaded".
 */
export const PYPI_NEVER_ABSENT = new Set(['psycopg', 'psycopg2', 'psycopg2-binary', 'psycopg-binary', 'psycopg-c', 'pymysql', 'mysqlclient', 'mysql-connector-python', 'cx-oracle', 'oracledb', 'pyodbc', 'asyncpg', 'aiomysql', 'aiosqlite', 'pg8000', 'pymssql', 'redis', 'hiredis', 'uvicorn', 'gunicorn', 'hypercorn', 'daphne', 'celery', 'uvloop', 'httptools', 'h11', 'h2', 'websockets', 'wsproto', 'watchfiles', 'setuptools', 'pip', 'wheel', 'distlib', 'virtualenv', 'pywin32', 'pywin32-ctypes', 'colorama', 'certifi', 'tzdata', 'six']);
const PY_IMPORT = /(?:^|[;:])[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b|import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*))/gm;

/** Python: modules imported (absolute imports), and every word of strings and of the other files. */
export async function pyUse(root, files, big) {
  const imported = new Map();
  const tokens = new Map();
  let code = 0;
  for (const f of files) {
    const isPy = /\.pyi?$/.test(f);
    const isNb = /\.ipynb$/.test(f);
    const isManifest = PY_MANIFEST.test(f);
    const isOther = isManifest || OPS.test(f) || /\.(?:toml|json|xml)$/.test(f);
    if (!isPy && !isNb && !isOther) continue;
    if (LOCKS.test(f) && !isManifest) continue;
    let src = await readText(root, f, isPy || isNb ? big : null);
    if (src == null) continue;
    let L = liner(src);
    if (isNb) {
      try { src = JSON.parse(src).cells?.map((c) => [].concat(c.source ?? []).join('')).join('\n') ?? ''; } catch { src = ''; }
      L = liner(src);
    }
    if (isManifest) src = withoutDependencyLists(src);
    if (isPy || isNb) {
      code++;
      for (const m of src.matchAll(PY_IMPORT)) {
        const mods = m[1] ? [m[1]] : m[2].split(',').map((x) => x.trim().split(/\s+/)[0]);
        for (const mod of mods) {
          const parts = mod.split('.');
          add(imported, parts[0], f, L(m.index), 'imported');
          if (parts.length > 1) add(imported, `${parts[0]}.${parts[1]}`, f, L(m.index), 'imported');
        }
      }
      // Strings name modules too: importlib.import_module("x"), settings (INSTALLED_APPS, URLs "mysql+pymysql://").
      for (const m of src.matchAll(/(['"])((?:(?!\1)[^\n\\]){1,300})\1/g)) words(tokens, m[2], f, 'named', { dotted: true });
    } else words(tokens, src, f, 'named', { dotted: true });
  }
  return { imported, tokens, code };
}

/**
 * Installed distributions found in a virtual environment of the project: their modules (top_level.txt,
 * RECORD), whether they declare entry points (commands, plugins: loaded by name), and their commands.
 */
export async function installedPython(root) {
  const out = new Map();
  const envs = [];
  async function find(d, depth) {
    if (depth > 3) return;
    let entries;
    try { entries = await readdir(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory() || e.name === 'node_modules' || e.name === '.git') continue;
      const p = join(d, e.name);
      if (await exists(join(p, 'pyvenv.cfg'))) envs.push(p); else await find(p, depth + 1);
    }
  }
  await find(root, 0);
  for (const env of envs) {
    const sps = [];
    try { for (const lib of await readdir(join(env, 'lib'))) sps.push(join(env, 'lib', lib, 'site-packages')); } catch { sps.push(join(env, 'Lib', 'site-packages')); }
    for (const sp of sps) {
      let entries;
      try { entries = await readdir(sp); } catch { continue; }
      for (const e of entries.filter((x) => x.endsWith('.dist-info'))) {
        const dist = e.replace(/-[^-]+\.dist-info$/, '').toLowerCase().replace(/[-_.]+/g, '-');
        const mods = new Set();
        const commands = [];
        const top = await readText(sp, join(e, 'top_level.txt'));
        if (top) for (const l of top.split(/\r?\n/)) if (l.trim()) mods.add(l.trim().replace(/\//g, '.'));
        const rec = await readText(sp, join(e, 'RECORD'));
        for (const l of rec?.split(/\r?\n/) ?? []) {
          const p = l.split(',')[0];
          const bin = /^\.\.\/(?:\.\.\/)*(?:bin|Scripts)\/([^/]+?)(?:\.exe)?$/.exec(p);
          if (bin) { commands.push(bin[1]); continue; }
          const m = /^([A-Za-z_]\w*)(?:\/|\.py$|\.[^/]*\.(?:so|pyd)$)/.exec(p);
          if (!top && m && !p.includes('.dist-info/') && m[1] !== '__pycache__') mods.add(m[1]);
        }
        const ep = await readText(sp, join(e, 'entry_points.txt'));
        if (mods.size) out.set(dist, { modules: [...mods], entryPoints: Boolean(ep && /\[[^\]]+\]/.test(ep)), commands });
      }
    }
  }
  return out;
}

// ---------- Rust ----------
const RS_PATH = /\b([a-z_][a-z0-9_]*)::/g;
const RS_USE = /\b(?:use|extern\s+crate)\s+([a-z_][a-z0-9_]*)/g;
export async function rsUse(root, files, big) {
  const imported = new Map();
  let code = 0;
  for (const f of files) {
    if (!/\.rs$/.test(f)) continue;
    const src = await readText(root, f, big);
    if (src == null) continue;
    let L = liner(src);
    code++;
    for (const re of [RS_PATH, RS_USE]) for (const m of src.matchAll(re)) if (!['crate', 'self', 'super', 'std', 'core', 'alloc'].includes(m[1])) add(imported, m[1], f, L(m.index), 'used');
  }
  return { imported, code };
}
/**
 * Cargo.toml: renamed dependencies (`alias = { package = "real" }` or `[dependencies.alias]` with
 * `package = "real"`), and its path dependencies.
 */
export function cargoManifest(toml) {
  const t = String(toml);
  const renames = new Map();
  for (const m of t.matchAll(/^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}\n]*\bpackage\s*=\s*"([^"]+)"/gm)) renames.set(m[1].replace(/-/g, '_'), m[2]);
  const lines = t.split(/\r?\n/);
  let table = null;
  for (const l of lines) {
    const h = /^\s*\[(?:[^\]]*\.)?(?:dev-|build-)?dependencies\.([A-Za-z0-9_-]+)\]\s*$/.exec(l);
    if (/^\s*\[/.test(l)) table = h ? h[1] : null;
    else if (table) { const p = /^\s*package\s*=\s*"([^"]+)"/.exec(l); if (p) renames.set(table.replace(/-/g, '_'), p[1]); }
  }
  const paths = [...t.matchAll(/\bpath\s*=\s*"([^"]+)"/g)].map((m) => m[1]);
  return { renames, paths };
}

// ---------- PHP ----------
/** Class and namespace names anywhere in PHP, YAML, XML and NEON files (`use`, `::class`, strings, services). */
export async function phpUse(root, files, big) {
  const names = new Map();
  let code = 0;
  for (const f of files) {
    if (LOCKS.test(f)) continue;
    const isPhp = /\.php$/.test(f);
    if (!isPhp && !/\.(?:ya?ml|xml|neon|json)$/.test(f)) continue;
    const src = await readText(root, f, isPhp ? big : null);
    if (src == null) continue;
    let L = liner(src);
    if (isPhp) code++;
    for (const m of src.matchAll(/([A-Za-z_][A-Za-z0-9_]*(?:\\{1,2}[A-Za-z0-9_]+)+|[A-Z][A-Za-z0-9]*_[A-Za-z0-9_]+)/g)) add(names, m[1].replace(/\\\\/g, '\\'), f, L(m.index), 'used');
  }
  return { names, code };
}

// ---------- Ruby, .NET: evidence of use only, never of absence ----------
export async function rbUse(root, files, big) {
  const imported = new Map();
  let bundlerRequire = null;
  let code = 0;
  for (const f of files) {
    if (!/\.(?:rb|rake|gemspec)$|(?:^|\/)(?:Rakefile|config\.ru)$/.test(f)) continue;
    const src = await readText(root, f, big);
    if (src == null) continue;
    let L = liner(src);
    code++;
    for (const m of src.matchAll(/\brequire\s*\(?\s*['"]([^'"]+)['"]/g)) add(imported, m[1], f, L(m.index), 'required');
    const b = /\bBundler\.require\b/.exec(src);
    if (b && !bundlerRequire) bundlerRequire = { file: f, line: L(b.index)(), how: 'required by Bundler.require' };
  }
  return { imported, bundlerRequire, code };
}
export async function csUse(root, files, big) {
  const imported = new Map();
  let code = 0;
  for (const f of files) {
    if (!/\.(?:cs|fs|vb)$/.test(f)) continue;
    const src = await readText(root, f, big);
    if (src == null) continue;
    let L = liner(src);
    code++;
    for (const m of src.matchAll(/^\s*(?:global\s+)?(?:using|open|Imports)\s+(?:static\s+)?([A-Z][\w.]*)/gm)) add(imported, m[1], f, L(m.index), 'using');
  }
  return { imported, code };
}
