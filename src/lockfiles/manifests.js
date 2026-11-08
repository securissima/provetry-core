// SPDX-License-Identifier: AGPL-3.0-only
// Which dependencies did you ask for, as opposed to what they brought in? Some lock files do not say; the
// manifest next to them does. Read-only, small files, no parser beyond what each format needs here.
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { normalizePypi } from '../purl.js';

const MAX = 4 * 1024 * 1024;

async function read(dir, name) {
  try {
    const p = join(dir, name);
    const s = await stat(p);
    if (!s.isFile() || s.size > MAX) return null;
    return await readFile(p, 'utf8');
  } catch {
    return null;
  }
}

/** package.json, composer.json: the keys of the dependency objects. */
function jsonKeys(text, fields, skip = () => false) {
  try {
    const j = JSON.parse(text);
    const names = new Set();
    for (const f of fields) for (const k of Object.keys(j?.[f] ?? {})) if (!skip(k)) names.add(k);
    return names;
  } catch {
    return null;
  }
}

/** Cargo.toml: keys of [dependencies], [dev-dependencies], [build-dependencies], [workspace.dependencies], target tables included. */
export function cargoNames(text) {
  const names = new Set();
  let inDeps = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    const table = /^\[([^\]]+)\]$/.exec(line);
    if (table) {
      const t = table[1].trim();
      const sub = /(?:^|\.)(?:dev-|build-)?dependencies\.([A-Za-z0-9_-]+)$/.exec(t);
      if (sub) {
        names.add(sub[1]);
        inDeps = false;
      } else inDeps = /(?:^|\.)(?:dev-|build-)?dependencies$/.test(t);
      continue;
    }
    if (!inDeps) continue;
    const m = /^"?([A-Za-z0-9_-]+)"?(?:\.workspace)?\s*=/.exec(line);
    if (m) {
      const pkg = /package\s*=\s*"([^"]+)"/.exec(line);
      names.add(pkg ? pkg[1] : m[1]);
    }
  }
  return names;
}

/** pyproject.toml: PEP 621 dependencies and optional dependencies, dependency groups, Poetry tables. */
export function pyprojectNames(text) {
  const names = new Set();
  const add = (spec) => {
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(spec);
    if (m && m[1].toLowerCase() !== 'python') names.add(normalizePypi(m[1]));
  };
  let table = '';
  let inArray = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s#.*$/, '').trim();
    const t = /^\[([^\]]+)\]$/.exec(line);
    if (t && !inArray) {
      table = t[1].trim();
      const poetryTable = /^tool\.poetry(?:\.group\.[^.]+)?\.(?:dev-)?dependencies\.([A-Za-z0-9][A-Za-z0-9._-]*)$/.exec(table);
      if (poetryTable) add(poetryTable[1]);
      continue;
    }
    const arrayTable = table === 'project' || table === 'project.optional-dependencies' || table === 'dependency-groups' || table === 'tool.uv';
    const items = (l) => l.replace(/\{[^}]*\}/g, ''); // skip {include-group = "…"} entries
    if (inArray) {
      for (const s of items(line).matchAll(/"([^"]+)"|'([^']+)'/g)) add(s[1] ?? s[2]);
      if (line.includes(']')) inArray = false;
      continue;
    }
    if (arrayTable) {
      const a = /^([A-Za-z0-9_-]+)\s*=\s*\[(.*)$/.exec(line);
      if (a && (table !== 'project' || a[1] === 'dependencies') && (table !== 'tool.uv' || a[1] === 'dev-dependencies')) {
        for (const s of items(a[2]).matchAll(/"([^"]+)"|'([^']+)'/g)) add(s[1] ?? s[2]);
        inArray = !a[2].includes(']');
      }
      continue;
    }
    if (/^tool\.poetry(\.group\.[^.]+)?\.(dev-)?dependencies$/.test(table)) {
      const k = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/.exec(line);
      if (k) add(k[1]);
    }
  }
  return names;
}

/**
 * Names of the direct dependencies declared next to a lock file, or null when there is no manifest to read.
 * Python names come back normalised.
 */
/**
 * Gradle: the coordinates written in build.gradle(.kts) ("group:artifact:version" strings) and the
 * version-catalog aliases they use (libs.foo.bar → gradle/libs.versions.toml, in this folder or above).
 */
export async function gradleNames(dir) {
  const build = (await read(dir, 'build.gradle.kts')) ?? (await read(dir, 'build.gradle'));
  if (build == null) return null;
  const names = new Set();
  for (const m of build.matchAll(/["']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::[^"'\s]*)?["']/g)) names.add(`${m[1]}:${m[2]}`);
  for (const m of build.matchAll(/\b(?:group|groupId)\s*[:=]\s*["']([^"']+)["']\s*,\s*(?:name|artifactId)\s*[:=]\s*["']([^"']+)["']/g)) names.add(`${m[1]}:${m[2]}`);
  const refs = new Set([...build.matchAll(/\blibs\.((?:[A-Za-z0-9]+\.?)+)/g)].map((m) => m[1].replace(/\.$/, '')));
  if (refs.size) {
    let catalog = null;
    for (let d = dir, i = 0; i < 4 && catalog == null; i++, d = join(d, '..')) catalog = await read(join(d, 'gradle'), 'libs.versions.toml');
    let section = '';
    for (const line of (catalog ?? '').split(/\r?\n/)) {
      const h = /^\s*\[([^\]]+)\]/.exec(line);
      if (h) { section = h[1].trim(); continue; }
      if (section !== 'libraries') continue;
      const k = /^\s*([A-Za-z0-9_-]+)\s*=\s*(.*)$/.exec(line);
      if (!k) continue;
      const alias = k[1].replace(/[-_]/g, '.');
      if (!refs.has(alias)) continue;
      const mod = /module\s*=\s*"([^":]+):([^"]+)"/.exec(k[2]) ?? /^"([^":]+):([^":]+)(?::[^"]*)?"/.exec(k[2].trim());
      const gn = /group\s*=\s*"([^"]+)"[^}]*\bname\s*=\s*"([^"]+)"/.exec(k[2]);
      const hit = mod ?? gn;
      if (hit) names.add(`${hit[1]}:${hit[2]}`);
    }
  }
  return names;
}

export async function manifestDirectNames(dir, lockName) {
  if (lockName === 'gradle.lockfile' || lockName === 'buildscript-gradle.lockfile') return gradleNames(dir);
  if (lockName === 'yarn.lock' || lockName === 'pnpm-lock.yaml') {
    const t = await read(dir, 'package.json');
    return t ? jsonKeys(t, ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) : null;
  }
  if (lockName === 'composer.lock') {
    const t = await read(dir, 'composer.json');
    return t ? jsonKeys(t, ['require', 'require-dev'], (k) => k === 'php' || k.startsWith('ext-') || k.startsWith('lib-')) : null;
  }
  if (lockName === 'Cargo.lock') {
    const t = await read(dir, 'Cargo.toml');
    return t ? cargoNames(t) : null;
  }
  if (lockName === 'poetry.lock' || lockName === 'uv.lock' || lockName === 'Pipfile.lock') {
    const t = await read(dir, 'pyproject.toml');
    if (t) return pyprojectNames(t);
    if (lockName === 'Pipfile.lock') {
      const pf = await read(dir, 'Pipfile');
      if (!pf) return null;
      const names = new Set();
      let on = false;
      for (const raw of pf.split(/\r?\n/)) {
        const line = raw.trim();
        if (/^\[/.test(line)) on = /^\[(dev-)?packages\]$/.test(line);
        else if (on) {
          const k = /^"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=/.exec(line);
          if (k) names.add(normalizePypi(k[1]));
        }
      }
      return names;
    }
  }
  return null;
}
