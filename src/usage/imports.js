// SPDX-License-Identifier: AGPL-3.0-only
// What the code of a project imports, read from its source files (nothing is executed): for each import
// name, the files and lines that import it. One reader per language; each says how an import name maps
// to a component, and whether that mapping is sure enough to conclude that a component is NOT imported.
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { normalizePypi } from '../purl.js';

const SKIP = new Set(['node_modules', '.git', '.hg', '.svn', 'vendor', 'dist', 'build', 'target', '.venv', 'venv', 'env', '__pycache__', '.next', '.nuxt', '.astro', '.svelte-kit', 'coverage', 'bin', 'obj', '.tox', '.mypy_cache']);
const MAX_FILE = 2 * 1024 * 1024;
const MAX_FILES = 50_000;

const EXT = {
  js: /\.(?:[cm]?[jt]sx?|vue|svelte|astro)$/,
  config: /\.(?:json|ya?ml|toml|[cm]?[jt]s|css|scss|sass|less|styl|html?|mdx)$|(?:^|\/)\.[a-z]+rc$/,
  py: /\.pyi?$/,
  rs: /\.rs$/,
  rb: /\.(?:rb|rake|gemspec)$|(?:^|\/)(?:Rakefile|config\.ru)$/,
  php: /\.php$/,
  cs: /\.(?:cs|fs|vb)$/,
};

/** Text files of the project under `dir` (not its dependencies), relative paths. */
export async function sourceFiles(dir, { skipNested = new Set() } = {}) {
  const out = [];
  async function walk(d) {
    let entries;
    try { entries = await readdir(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= MAX_FILES || e.isSymbolicLink()) continue;
      const p = join(d, e.name);
      if (e.isDirectory()) { if (!SKIP.has(e.name) && !skipNested.has(p)) await walk(p); }
      else if (e.isFile()) out.push(relative(dir, p));
    }
  }
  await walk(dir);
  return out.sort();
}

async function text(dir, f) {
  try {
    const s = await stat(join(dir, f));
    if (s.size > MAX_FILE) return null;
    return await readFile(join(dir, f), 'utf8');
  } catch { return null; }
}

/** Adds an occurrence: name → [{ file, line }], a few per name are enough as evidence. */
function add(map, name, file, line) {
  const list = map.get(name) ?? map.set(name, []).get(name);
  if (list.length < 5 && !list.some((x) => x.file === file)) list.push({ file, line });
}
const lineAt = (src, index) => src.slice(0, index).split('\n').length;

// ---------- JavaScript / TypeScript ----------
const NODE_BUILTINS = new Set(['assert', 'buffer', 'child_process', 'cluster', 'console', 'constants', 'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'http2', 'https', 'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline', 'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib', 'async_hooks', 'diagnostics_channel', 'inspector', 'trace_events', 'test']);
/** "lodash/fp" → "lodash", "@scope/pkg/x" → "@scope/pkg"; null for relative paths and built-ins. */
export function npmPackageOf(spec) {
  if (!spec || /^[./~#]|^[a-z]+:/i.test(spec) && !/^@/.test(spec)) return null;
  const parts = spec.split('/');
  const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  if (!/^(?:@[a-z0-9._~-]+\/)?[a-z0-9._~-]+$/i.test(name) || NODE_BUILTINS.has(name)) return null;
  return name;
}
const JS_IMPORT = /\b(?:import|export)\s+(?:type\s+)?(?:[^'"`;]*?\s+from\s+)?['"]([^'"\n]+)['"]|\b(?:require|import|require\.resolve)\s*\(\s*['"`]([^'"`\n]+)['"`]\s*\)/g;
const QUOTED = /['"`(](?:~|\.{0,2}\/?node_modules\/)?(@?[A-Za-z0-9._/-]{1,214})['"`)]/g;

/**
 * npm: `import`/`require` in the code, and also any package named in a string anywhere in the project's
 * own files (configs that load plugins by name, scripts that run a tool): named means possibly used.
 */
export async function jsImports(dir, files) {
  const imported = new Map();
  const named = new Map();
  const scripts = [];
  for (const f of files) {
    const isCode = EXT.js.test(f);
    if (!isCode && !EXT.config.test(f) && !/(?:^|\/)package\.json$/.test(f)) continue;
    if (/(?:^|\/)(?:package-lock|npm-shrinkwrap|composer|packages\.lock)\.json$|pnpm-lock\.yaml$/.test(f)) continue;
    let src = await text(dir, f);
    if (src == null) continue;
    if (/(?:^|\/)package\.json$/.test(f)) {
      // The dependency lists name every direct dependency: they are not a use. Scripts and settings are.
      try {
        const pj = JSON.parse(src);
        for (const k of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundleDependencies', 'bundledDependencies', 'overrides', 'resolutions', 'peerDependenciesMeta', 'dependenciesMeta', 'name', 'workspaces', 'pnpm']) delete pj[k];
        for (const v of Object.values(pj.scripts ?? {})) scripts.push({ file: f, text: String(v) });
        src = JSON.stringify(pj, null, 1);
      } catch { /* not JSON: read as text */ }
    }
    if (isCode) for (const m of src.matchAll(JS_IMPORT)) { const p = npmPackageOf(m[1] ?? m[2]); if (p) add(imported, p, f, lineAt(src, m.index)); }
    for (const m of src.matchAll(QUOTED)) { const p = npmPackageOf(m[1]); if (p) add(named, p, f, lineAt(src, m.index)); }
  }
  return { imported, named, scripts };
}

// ---------- Python ----------
/**
 * Distribution name → the modules it installs, when they differ from the name. Anything not here, and not
 * found in an installed environment, is "not sure": no conclusion of absence is drawn from it.
 */
export const PYPI_MODULES = {
  beautifulsoup4: ['bs4'], pyyaml: ['yaml'], pillow: ['PIL'], 'scikit-learn': ['sklearn'], 'python-dateutil': ['dateutil'],
  'opencv-python': ['cv2'], 'opencv-python-headless': ['cv2'], protobuf: ['google.protobuf'], attrs: ['attr', 'attrs'], pyjwt: ['jwt'],
  'python-dotenv': ['dotenv'], pycryptodome: ['Crypto'], pycryptodomex: ['Cryptodome'], pyopenssl: ['OpenSSL'], 'psycopg2-binary': ['psycopg2'],
  'typing-extensions': ['typing_extensions'], setuptools: ['setuptools', 'pkg_resources', '_distutils_hack'], 'google-auth': ['google.auth', 'google.oauth2'],
  'msgpack-python': ['msgpack'], pymysql: ['pymysql'], 'mysql-connector-python': ['mysql.connector'], 'python-multipart': ['multipart', 'python_multipart'],
  'python-jose': ['jose'], 'python-magic': ['magic'], 'pywin32': ['win32api', 'win32con', 'pywintypes'], dnspython: ['dns'], 'pyzmq': ['zmq'],
  'scikit-image': ['skimage'], 'ruamel.yaml': ['ruamel.yaml'], 'zope.interface': ['zope.interface'], 'jaraco.classes': ['jaraco.classes'],
  'importlib-metadata': ['importlib_metadata'], 'importlib-resources': ['importlib_resources'], 'charset-normalizer': ['charset_normalizer'],
  'websocket-client': ['websocket'], 'grpcio': ['grpc'], 'markdown-it-py': ['markdown_it'], 'mdit-py-plugins': ['mdit_py_plugins'],
};
const PY_IMPORT = /^[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b|import[ \t]+([A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*(?:[ \t]+as[ \t]+\w+)?)*))/gm;

/** Python: dotted module names imported (absolute imports only). */
export async function pyImports(dir, files) {
  const imported = new Map();
  for (const f of files) {
    if (!EXT.py.test(f)) continue;
    const src = await text(dir, f);
    if (src == null) continue;
    for (const m of src.matchAll(PY_IMPORT)) {
      const mods = m[1] ? [m[1]] : m[2].split(',').map((x) => x.trim().split(/\s+/)[0]);
      for (const mod of mods) {
        const parts = mod.split('.');
        add(imported, parts[0], f, lineAt(src, m.index));
        if (parts.length > 1) add(imported, `${parts[0]}.${parts[1]}`, f, lineAt(src, m.index));
      }
    }
  }
  return { imported };
}

/** Modules of installed distributions, from a virtual environment inside the project (top_level.txt, RECORD). */
export async function installedPyModules(dir) {
  const out = new Map();
  for (const env of ['.venv', 'venv', 'env']) {
    let libs;
    try { libs = await readdir(join(dir, env, 'lib')); } catch { try { libs = ['..']; await stat(join(dir, env, 'Lib', 'site-packages')); } catch { continue; } }
    for (const lib of libs) {
      const sp = lib === '..' ? join(dir, env, 'Lib', 'site-packages') : join(dir, env, 'lib', lib, 'site-packages');
      let entries;
      try { entries = await readdir(sp); } catch { continue; }
      for (const e of entries.filter((x) => x.endsWith('.dist-info'))) {
        const dist = normalizePypi(e.replace(/-[^-]+\.dist-info$/, ''));
        const mods = new Set();
        const top = await text(sp, join(e, 'top_level.txt'));
        if (top) for (const l of top.split(/\r?\n/)) if (l.trim()) mods.add(l.trim().replace(/\//g, '.'));
        if (!mods.size) {
          const rec = await text(sp, join(e, 'RECORD'));
          for (const l of rec?.split(/\r?\n/) ?? []) {
            const p = l.split(',')[0];
            const m = /^([A-Za-z_]\w*)(?:\/|\.py$)/.exec(p);
            if (m && !p.includes('.dist-info/') && !p.startsWith('..') && m[1] !== '__pycache__') mods.add(m[1]);
          }
        }
        if (mods.size) out.set(dist, [...mods]);
      }
    }
  }
  return out;
}

// ---------- Rust ----------
const RS_PATH = /\b([a-z_][a-z0-9_]*)::/g;
const RS_USE = /\b(?:use|extern\s+crate)\s+([a-z_][a-z0-9_]*)/g;
export async function rsImports(dir, files) {
  const imported = new Map();
  for (const f of files) {
    if (!EXT.rs.test(f)) continue;
    const src = await text(dir, f);
    if (src == null) continue;
    for (const re of [RS_PATH, RS_USE]) for (const m of src.matchAll(re)) if (!['crate', 'self', 'super', 'std', 'core', 'alloc'].includes(m[1])) add(imported, m[1], f, lineAt(src, m.index));
  }
  return { imported };
}
/** Cargo.toml renames: `alias = { package = "real" }` → real crate imported under the alias. */
export function cargoRenames(toml) {
  const out = new Map();
  for (const m of String(toml).matchAll(/^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}\n]*\bpackage\s*=\s*"([^"]+)"/gm)) out.set(m[1].replace(/-/g, '_'), m[2]);
  return out;
}

// ---------- Ruby ----------
export async function rbImports(dir, files) {
  const imported = new Map();
  let bundlerRequire = null;
  for (const f of files) {
    if (!EXT.rb.test(f)) continue;
    const src = await text(dir, f);
    if (src == null) continue;
    for (const m of src.matchAll(/\brequire\s*\(?\s*['"]([^'"]+)['"]/g)) add(imported, m[1], f, lineAt(src, m.index));
    const b = /\bBundler\.require\b/.exec(src);
    if (b && !bundlerRequire) bundlerRequire = { file: f, line: lineAt(src, b.index) };
  }
  return { imported, bundlerRequire };
}

// ---------- PHP ----------
export async function phpImports(dir, files) {
  const imported = new Map();
  for (const f of files) {
    if (!EXT.php.test(f)) continue;
    const src = await text(dir, f);
    if (src == null) continue;
    for (const m of src.matchAll(/(?:\buse\s+(?:function\s+|const\s+)?|\\?\bnew\s+\\?|[\s(,=]\\)([A-Z][A-Za-z0-9_]*(?:\\[A-Za-z0-9_]+)+)/g)) add(imported, m[1].replace(/^\\/, ''), f, lineAt(src, m.index));
  }
  return { imported };
}

// ---------- .NET ----------
export async function csImports(dir, files) {
  const imported = new Map();
  for (const f of files) {
    if (!EXT.cs.test(f)) continue;
    const src = await text(dir, f);
    if (src == null) continue;
    for (const m of src.matchAll(/^\s*(?:global\s+)?(?:using|open|Imports)\s+(?:static\s+)?([A-Z][\w.]*)/gm)) add(imported, m[1], f, lineAt(src, m.index));
  }
  return { imported };
}
