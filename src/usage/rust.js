// SPDX-License-Identifier: AGPL-3.0-only
// Function level for Rust, from the advisory itself: RustSec names the affected functions of a crate
// ("smallvec::SmallVec::insert_many"). When the project's own code is the only thing that loads the crate,
// and no file of the repository even mentions any of those functions, the vulnerable code is not called.
// A name that appears anywhere counts as a call (methods, re-exports, function pointers). Macros of the
// crate can call its functions from inside the project's code: their use stops any conclusion.
import { projectFiles, readText, cargoManifest } from './imports.js';

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Methods that Rust calls without their name in the source (operators, loops, `.await`, drops, formatting,
 * derives, generic code of other crates through a trait): an affected function with one of these names, or
 * written as `<T as Trait>::f`, stops any conclusion.
 */
export const IMPLICIT = new Set(['drop', 'deref', 'deref_mut', 'index', 'index_mut', 'next', 'next_back', 'poll', 'fmt', 'eq', 'ne', 'cmp', 'partial_cmp', 'lt', 'le', 'gt', 'ge', 'hash', 'clone', 'clone_from', 'from', 'into', 'try_from', 'try_into', 'from_str', 'as_ref', 'as_mut', 'borrow', 'borrow_mut', 'serialize', 'deserialize', 'visit_str', 'read', 'read_exact', 'read_to_end', 'write', 'write_all', 'flush', 'extend', 'from_iter', 'into_iter', 'default', 'call', 'call_mut', 'call_once', 'add', 'sub', 'mul', 'div', 'rem', 'neg', 'not', 'shl', 'shr', 'bitand', 'bitor', 'bitxor', 'add_assign', 'sub_assign', 'mul_assign', 'div_assign', 'size_hint', 'len', 'to_string', 'to_owned', 'encode', 'decode', 'new']);

/** Last segment of an affected path, without generics: "smallvec::SmallVec::<A>::insert_many" → "insert_many". */
export function functionName(path) {
  const parts = String(path).replace(/<[^<>]*>/g, '').split('::').filter(Boolean);
  return parts.at(-1) ?? '';
}

/**
 * For each finding on a Cargo crate the code imports, with affected functions named: { result, ... }.
 * result "mentioned": a function name appears (file and line); "not_mentioned": none does; null: no conclusion.
 */
export async function rustFunctions(root, findings, components) {
  const todo = findings.filter((f) => f.component.type === 'cargo' && f.functions?.length);
  const out = new Map();
  if (!todo.length) return out;
  const { files, incomplete } = await projectFiles(root);
  if (incomplete) return out;
  const sources = [];
  const renames = new Map();
  let generated = null;
  for (const f of files) {
    if (/\.rs$/.test(f)) {
      const t = await readText(root, f);
      if (t == null) return out;
      sources.push([f, t]);
      // Code generated at build time (prost, tonic, bindgen…) is not in the repository.
      if (/\binclude!\s*\(\s*concat!\s*\(\s*env!\s*\(\s*"OUT_DIR"/.test(t)) generated ??= f;
    }
    else if (/(?:^|\/)Cargo\.toml$/.test(f)) for (const [a, real] of cargoManifest(await readText(root, f) ?? '').renames) renames.set(real, [...(renames.get(real) ?? []), a]);
  }
  for (const f of todo) {
    const u = components.get(f.component.purl);
    if (!u || u.state !== 'imported' || u.byTool || u.alsoLoadedBy?.length) continue;
    const name = f.component.name;
    const crates = [...new Set([name.replace(/-/g, '_'), name.replace(/-/g, ''), ...(renames.get(name) ?? [])])];
    // Aliases: "use c as d;", "extern crate c as d;".
    for (const [, src] of sources) for (const c of [...crates]) for (const m of src.matchAll(new RegExp(`\\b(?:use|extern\\s+crate)\\s+${escapeRe(c)}\\s+as\\s+([A-Za-z_]\\w*)`, 'g'))) crates.push(m[1]);
    if (generated) continue;
    // A build script that uses the crate, or its "-build" companion, writes code that calls it.
    if (sources.some(([file, src]) => /(?:^|\/)build\.rs$/.test(file) && crates.some((c) => new RegExp(`\\b${escapeRe(c)}(?:_build)?\\b`).test(src)))) continue;
    const names = [...new Set(f.functions.map(functionName))];
    if (!names.length || names.some((n) => !/^[A-Za-z_]\w*$/.test(n) || IMPLICIT.has(n) || /^poll_|^visit_|^serialize_|^deserialize_|^try_poll/.test(n))) continue;
    if (f.functions.some((p) => /^\s*</.test(p) || /\bas\b/.test(p))) continue;
    let blocked = null;
    let hit = null;
    for (const [file, src] of sources) {
      for (const c of crates) {
        // The crate's macros (function-like, attributes, derives) expand inside the project's code, where
        // they may call anything of the crate; re-exported, they can be used under another name anywhere.
        if (new RegExp(`#\\[macro_use\\]\\s*extern\\s+crate\\s+${escapeRe(c)}\\b|\\b${escapeRe(c)}::[A-Za-z_][\\w:]*!|#!?\\[\\s*${escapeRe(c)}::|#\\[derive\\([^\\]]*\\b${escapeRe(c)}::`).test(src)) blocked ??= `${file} uses macros of ${c}`;
        if (new RegExp(`\\bpub(?:\\([^)]*\\))?\\s+use\\s+${escapeRe(c)}::`).test(src)) blocked ??= `${file} re-exports ${c}`;
        for (const m of src.matchAll(new RegExp(`\\buse\\s+${escapeRe(c)}::([^;]+);`, 'g'))) {
          for (const id of m[1].match(/[A-Za-z_]\w*/g) ?? []) {
            if (id === 'self' || id === 'super' || id === 'crate') continue;
            if (new RegExp(`\\b${escapeRe(id)}!|#!?\\[\\s*${escapeRe(id)}\\b|#\\[derive\\([^\\]]*\\b${escapeRe(id)}\\b`).test(src)) blocked ??= `${file} uses the macro ${id} of ${c}`;
          }
          if (/\*/.test(m[1])) blocked ??= `${file} imports everything of ${c} (macros included)`;
        }
      }
      if (!hit) {
        for (const n of names) {
          const m = new RegExp(`\\b${escapeRe(n)}\\b`).exec(src);
          if (m) { hit = { name: n, file, line: src.slice(0, m.index).split('\n').length }; break; }
        }
      }
    }
    if (hit) out.set(`${f.id}|${f.component.purl}`, { result: 'mentioned', ...hit });
    else if (!blocked) out.set(`${f.id}|${f.component.purl}`, { result: 'not_mentioned', names });
  }
  return out;
}
