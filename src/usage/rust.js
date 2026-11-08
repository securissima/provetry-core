// SPDX-License-Identifier: AGPL-3.0-only
// Function level for Rust, from the advisory itself: RustSec names the affected functions of a crate
// ("smallvec::SmallVec::insert_many"). When the project's own code is the only thing that loads the crate,
// and no file of the repository even mentions any of those functions, the vulnerable code is not called.
// A name that appears anywhere counts as a call (methods, re-exports, function pointers). Macros of the
// crate can call its functions from inside the project's code: their use stops any conclusion.
import { projectFiles, readText, cargoManifest } from './imports.js';

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

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
  for (const f of files) {
    if (/\.rs$/.test(f)) { const t = await readText(root, f); if (t == null) return out; sources.push([f, t]); }
    else if (/(?:^|\/)Cargo\.toml$/.test(f)) for (const [a, real] of cargoManifest(await readText(root, f) ?? '').renames) renames.set(real, [...(renames.get(real) ?? []), a]);
  }
  for (const f of todo) {
    const u = components.get(f.component.purl);
    if (!u || u.state !== 'imported' || u.byTool || u.alsoLoadedBy?.length) continue;
    const name = f.component.name;
    const crates = [...new Set([name.replace(/-/g, '_'), name.replace(/-/g, ''), ...(renames.get(name) ?? [])])];
    const names = [...new Set(f.functions.map(functionName).filter((n) => /^[A-Za-z_]\w*$/.test(n)))];
    if (!names.length) continue;
    let blocked = null;
    let hit = null;
    for (const [file, src] of sources) {
      for (const c of crates) {
        // The crate's macros expand inside the project's code, where they may call anything of the crate.
        if (new RegExp(`#\\[macro_use\\]\\s*extern\\s+crate\\s+${escapeRe(c)}\\b|\\b${escapeRe(c)}::[A-Za-z_]\\w*!`).test(src)) blocked ??= `${file} uses macros of ${c}`;
        for (const m of src.matchAll(new RegExp(`\\buse\\s+${escapeRe(c)}::([^;]+);`, 'g'))) {
          for (const id of m[1].match(/[A-Za-z_]\w*/g) ?? []) if (new RegExp(`\\b${escapeRe(id)}!`).test(src)) blocked ??= `${file} uses the macro ${id} of ${c}`;
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
