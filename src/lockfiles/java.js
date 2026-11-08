// SPDX-License-Identifier: AGPL-3.0-only
// Java (and Kotlin, Scala on the JVM): Gradle's dependency lock files, which list every resolved component,
// and Maven's pom.xml, which lists the direct dependencies only (Maven has no lock file: the full tree needs
// Maven itself, or an SBOM from the CycloneDX Maven plugin, which `provetry scan` reads).
import { makePurl } from '../purl.js';

const comp = (name, version, extra = {}) => ({ type: 'maven', name, version, purl: makePurl('maven', name, version), scope: 'required', ...extra });
const TEST_ONLY = /^(?:test|androidTest|testFixtures|integrationTest|functionalTest)[A-Z]|^test$|TestCompileClasspath$|TestRuntimeClasspath$|UnitTest|AndroidTest/;

/**
 * gradle.lockfile (Gradle 6.8+): "group:artifact:version=configuration,configuration". A component only in
 * test configurations is a development dependency; one in buildscript-gradle.lockfile builds the product
 * and does not ship in it.
 */
export function parseGradleLock(text, { buildscript = false } = {}) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('empty=')) continue;
    const m = /^([^:=\s]+):([^:=\s]+):([^:=\s]+)=(.*)$/.exec(line);
    if (!m) throw new Error(`unexpected line: ${line.slice(0, 80)}`);
    const confs = m[4].split(',').map((c) => c.trim()).filter(Boolean);
    const dev = buildscript || (confs.length > 0 && confs.every((c) => TEST_ONLY.test(c)));
    out.push(comp(`${m[1]}:${m[2]}`, m[3], { scope: dev ? 'dev' : 'required' }));
  }
  return out;
}

// ---------- pom.xml ----------
const tag = (xml, name) => {
  const m = new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`).exec(xml);
  return m ? m[1] : null;
};
/** The top-level children of an element, by name (no nesting of the same name inside). */
function blocks(xml, name) {
  return [...xml.matchAll(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'g'))].map((m) => m[1]);
}
const stripComments = (xml) => xml.replace(/<!--[\s\S]*?-->/g, '');
/** Removes nested elements that would be mistaken for the project's own (plugins, profiles, management). */
function withoutSections(xml, names) {
  let out = xml;
  for (const n of names) out = out.replace(new RegExp(`<${n}(?:\\s[^>]*)?>[\\s\\S]*?</${n}>`, 'g'), '');
  return out;
}

/**
 * pom.xml: the direct dependencies, versions resolved from the properties and the dependency management of
 * this file. Returns { components, unresolved } (unresolved: "group:artifact" whose version comes from a
 * parent or an imported BOM, which only Maven can resolve).
 */
export function readPom(text) {
  const xml = stripComments(text);
  const parent = blocks(xml, 'parent')[0] ?? '';
  const top = withoutSections(xml, ['parent', 'build', 'profiles', 'reporting', 'dependencyManagement', 'pluginRepositories', 'repositories', 'distributionManagement']);
  const props = new Map();
  for (const p of blocks(xml, 'properties')) for (const m of p.matchAll(/<([A-Za-z0-9_.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(m[1], m[2]);
  const groupId = tag(top.replace(/<dependencies>[\s\S]*<\/dependencies>/, ''), 'groupId') ?? tag(parent, 'groupId');
  const version = tag(top.replace(/<dependencies>[\s\S]*<\/dependencies>/, ''), 'version') ?? tag(parent, 'version');
  for (const [k, v] of [['project.groupId', groupId], ['pom.groupId', groupId], ['project.version', version], ['pom.version', version], ['project.parent.version', tag(parent, 'version')], ['parent.version', tag(parent, 'version')]]) if (v) props.set(k, v);
  const expand = (s, depth = 0) => (s && depth < 10 && /\$\{/.test(s) ? expand(s.replace(/\$\{([^}]+)\}/g, (all, k) => props.get(k) ?? all), depth + 1) : s);
  const managed = new Map();
  for (const dm of blocks(xml, 'dependencyManagement')) {
    for (const d of blocks(dm, 'dependency')) {
      const g = expand(tag(d, 'groupId')); const a = expand(tag(d, 'artifactId')); const v = expand(tag(d, 'version'));
      if (g && a && v && tag(d, 'scope') !== 'import') managed.set(`${g}:${a}`, v);
    }
  }
  const components = [];
  const unresolved = [];
  const deps = blocks(top, 'dependencies')[0] ?? '';
  for (const d of blocks(deps, 'dependency')) {
    const g = expand(tag(d, 'groupId'));
    const a = expand(tag(d, 'artifactId'));
    if (!g || !a) continue;
    const scope = tag(d, 'scope') ?? 'compile';
    if (scope === 'system' || scope === 'import') continue;
    let v = expand(tag(d, 'version')) ?? managed.get(`${g}:${a}`) ?? null;
    if (v) v = v.replace(/^\[([^,\]]+)\]$/, '$1'); // "[1.2.3]" is an exact version
    if (!v || /\$\{|[[\](),]/.test(v)) { unresolved.push(`${g}:${a}`); continue; }
    // A module of the same project, at the project's own version: the product itself, not a dependency.
    if (g === groupId && v === version) continue;
    components.push(comp(`${g}:${a}`, v, { direct: true, scope: scope === 'test' || scope === 'provided' ? 'dev' : tag(d, 'optional') === 'true' ? 'optional' : 'required' }));
  }
  return { components, unresolved };
}

export function parsePom(text) {
  const { components, unresolved } = readPom(text);
  const out = [...components];
  // Said, not hidden: the caller reports these (no version here means a parent POM or a BOM decides it).
  Object.defineProperty(out, 'notice', {
    value: `lists the direct dependencies only${unresolved.length ? `, and ${unresolved.length} without a version here (set by a parent POM or a BOM: ${unresolved.slice(0, 3).join(', ')}${unresolved.length > 3 ? '…' : ''})` : ''}; for the full tree, pass an SBOM from the CycloneDX Maven plugin`,
    enumerable: false,
  });
  return out;
}
