// SPDX-License-Identifier: AGPL-3.0-only
// Function level for npm and PyPI, from open data: Provetry's vulnerable-functions records
// (github.com/Enigmacker/provetry-vulnerable-functions) give, for an advisory, the public functions of the
// package that lead to the code its fix changed. When the project's own code is the only thing that loads
// the package and no file of the repository mentions any of those functions, the vulnerable code is not
// called through them. Nothing is concluded when the record has no function-level answer ("whole"), when
// methods lead to the fix (frameworks call methods without the product writing their names), or when
// anything else may call the package.
import { projectFiles, readText } from './imports.js';
import { cacheGet, cacheSet, getJson } from '../util.js';
import { normalizePypi } from '../purl.js';

// The data is read at a fixed commit, moved deliberately with each release of this tool: whoever can push
// to the data repository cannot change what a release concludes. Null: not published yet, nothing is read.
export const DATA_REF = null;
export const DATA_URL = DATA_REF ? `https://raw.githubusercontent.com/Enigmacker/provetry-vulnerable-functions/${DATA_REF}/data` : null;
const METHOD = /^provetry-vulnerable-functions\/2 \(/;
const MAX_AGE = 24 * 3600;
const ID = /^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$/;

// Called without their name in the code that uses them: no conclusion when one is an entry point.
const IMPLICIT = new Set(['toString', 'valueOf', 'toJSON', 'then', 'catch', 'finally', 'next', 'get', 'set', 'has', 'apply', 'call', 'bind', 'default', 'constructor', 'handler', 'main', 'run', 'init', 'setup', 'register', 'middleware', 'plugin', 'install']);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The records for the findings' advisories (npm, PyPI): Map "id|purl" → record of that package. */
export async function loadFunctionData(ctx, findings, { baseUrl = DATA_URL } = {}) {
  const out = new Map();
  if (!baseUrl) return out;
  const wanted = findings.filter((f) => f.component.type === 'npm' || f.component.type === 'pypi');
  const byId = new Map();
  for (const f of wanted) {
    const id = f.ids.find((x) => ID.test(x));
    if (!id) continue;
    if (!byId.has(id)) {
      let records = cacheGet(ctx, `pvf:${id}`, MAX_AGE);
      if (records == null) {
        try {
          const { status, json } = await getJson(ctx, `${baseUrl}/${id}.json`);
          records = status === 200 && Array.isArray(json) ? json : [];
          // A missing record is an answer; a server error is not (tried again next time).
          if (status === 200 || status === 404) cacheSet(ctx, `pvf:${id}`, records);
        } catch { records = []; }
      }
      // Only records of this advisory, made by the method this release knows.
      records = (records ?? []).filter((r) => r && r.id === id && METHOD.test(String(r.method ?? '')) && typeof r.version === 'string' && Array.isArray(r.entryPoints) && Array.isArray(r.methods) && typeof r.whole === 'boolean');
      byId.set(id, records ?? []);
    }
    const name = f.component.type === 'pypi' ? normalizePypi(f.component.name) : f.component.name;
    const rec = byId.get(id).find((r) => (r.ecosystem === 'npm' && f.component.type === 'npm' && r.package === name) || (r.ecosystem === 'PyPI' && f.component.type === 'pypi' && normalizePypi(r.package) === name));
    if (rec) out.set(`${f.id}|${f.component.purl}`, { ...rec, advisory: id });
  }
  return out;
}

/**
 * For each finding with a usable record: { result: "mentioned" | "not_mentioned", names, source }.
 * Same conditions as for Rust: the package is imported by the project's own code only.
 */
export async function packageFunctions(root, findings, components, data) {
  const out = new Map();
  const todo = findings.filter((f) => data.has(`${f.id}|${f.component.purl}`));
  if (!todo.length) return out;
  const { files, incomplete } = await projectFiles(root);
  if (incomplete) return out;
  const texts = new Map();
  const textsOf = async (re) => {
    const list = [];
    for (const f of files) {
      if (!re.test(f) || /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|uv\.lock|Pipfile\.lock|requirements[^/]*\.txt)$/.test(f)) continue;
      if (!texts.has(f)) texts.set(f, await readText(root, f));
      if (texts.get(f) == null) return null; // a file too large to read: no conclusion
      list.push([f, texts.get(f)]);
    }
    return list;
  };
  for (const f of todo) {
    const rec = data.get(`${f.id}|${f.component.purl}`);
    const u = components.get(f.component.purl);
    if (rec.whole || rec.methods?.length || !rec.entryPoints?.length) continue;
    // Computed on one version: another major or minor version may use other names.
    const mm = (v) => String(v).split('.').slice(0, 2).join('.');
    if (mm(rec.version) !== mm(f.component.version)) continue;
    if (!u || u.state !== 'imported' || u.byTool || u.alsoLoadedBy?.length) continue;
    const names = rec.entryPoints.filter((n) => !n.startsWith('module:'));
    const modules = rec.entryPoints.filter((n) => n.startsWith('module:')).map((n) => n.slice(7));
    if (names.some((n) => IMPLICIT.has(n) || !/^[A-Za-z_$][\w$]*$/.test(n))) continue;
    // Every file of the project that could name a function: code, configuration, scripts.
    const sources = await textsOf(f.component.type === 'npm' ? /\.(?:[cm]?[jt]sx?|vue|svelte|astro|json|ya?ml|toml|html?|mdx|sh)$|(?:^|\/)(?:Dockerfile|Makefile)[^/]*$/ : /\.(?:pyi?|ipynb|toml|cfg|ini|ya?ml|json|sh|txt)$|(?:^|\/)(?:Dockerfile|Makefile|Procfile)[^/]*$/);
    if (sources == null) continue;
    let hit = null;
    for (const [file, src] of sources) {
      for (const n of names) {
        const m = new RegExp(`(?<![\\w$])${escapeRe(n)}(?![\\w$])`).exec(src);
        if (m) { hit = { name: n, file, line: src.slice(0, m.index).split('\n').length }; break; }
      }
      for (const sub of modules) {
        const m = new RegExp(`['"\`]${escapeRe(f.component.name)}/${escapeRe(sub)}(?:\\.[cm]?js)?['"\`]`).exec(src);
        if (m && !hit) { hit = { name: `${f.component.name}/${sub}`, file, line: src.slice(0, m.index).split('\n').length }; }
      }
      if (hit) break;
    }
    const source = `Provetry vulnerable-functions data for ${rec.advisory} (from its fix)`;
    out.set(`${f.id}|${f.component.purl}`, hit ? { result: 'mentioned', ...hit, source } : { result: 'not_mentioned', names: rec.entryPoints, source });
  }
  return out;
}
