// SPDX-License-Identifier: AGPL-3.0-only
// Java (and Kotlin, Scala on the JVM): Gradle's dependency lock files, which list every resolved component,
// and Maven's pom.xml, which lists the direct dependencies only (Maven has no lock file: the full tree needs
// Maven itself, or an SBOM from the CycloneDX Maven plugin, which `provetry scan` reads). What pom.xml
// cannot give is said in a notice, carried into the SBOM (marked incomplete) and the scan report.
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve, basename } from 'node:path';
import { makePurl } from '../purl.js';

const comp = (name, version, extra = {}) => ({ type: 'maven', name, version, purl: makePurl('maven', name, version), scope: 'required', ...extra });

const TEST = /^test$|^(?:test|androidTest|testFixtures|integrationTest|functionalTest)[A-Z]|[a-z]Test(?:Compile|Runtime)Classpath$|UnitTest|AndroidTest/;
const RUNTIME = /(?:^|[a-z])[Rr]untimeClasspath$/;

/**
 * gradle.lockfile (Gradle 6.8+): "group:artifact:version=configuration,configuration". Shipped means in a
 * runtime classpath that is not a test one (and, when release variants exist, not a debug-only one);
 * anything else (compile-only, annotation processors, linters, test, the build script) does not ship.
 * Gradle before 6.8 kept one file per configuration (gradle/dependency-locks/<configuration>.lockfile,
 * "group:artifact:version" lines): `configuration` names it then.
 */
export function parseGradleLock(text, { buildscript = false, configuration = null } = {}) {
  const rows = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('empty=')) continue;
    const m = /^([^:=\s]+):([^:=\s]+):([^:=\s]+)(?:=(.*))?$/.exec(line);
    if (!m) throw new Error(`unexpected line: ${line.slice(0, 80)}`);
    const confs = (m[4] !== undefined ? m[4].split(',') : configuration ? [configuration] : []).map((c) => c.trim()).filter(Boolean);
    rows.push({ name: `${m[1]}:${m[2]}`, version: m[3], confs });
  }
  const hasRelease = rows.some((r) => r.confs.some((c) => /^release/i.test(c) && RUNTIME.test(c)));
  return rows.map((r) => {
    const ships = !buildscript && r.confs.some((c) => RUNTIME.test(c) && !TEST.test(c) && !(hasRelease && /^debug/i.test(c)));
    // No configuration known (a legacy file of unknown purpose): counted as shipped rather than left out.
    return comp(r.name, r.version, { scope: ships || (!buildscript && !r.confs.length) ? 'required' : 'dev' });
  });
}

// ---------- pom.xml ----------
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const clean = (s) => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/&(amp|lt|gt|quot|apos);/g, (_, e) => ENTITIES[e]).trim();
const tag = (xml, name) => {
  const m = new RegExp(`<(?:[\\w-]+:)?${name}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>`).exec(xml);
  return m ? clean(m[1]) : null;
};
/** The children of an element, by name. */
const blocks = (xml, name) => [...xml.matchAll(new RegExp(`<(?:[\\w-]+:)?${name}(?:\\s[^>]*)?>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>`, 'g'))].map((m) => m[1]);
const without = (xml, names) => names.reduce((x, n) => x.replace(new RegExp(`<(?:[\\w-]+:)?${n}(?:\\s[^>]*)?>[\\s\\S]*?</(?:[\\w-]+:)?${n}>`, 'g'), ''), xml);
const props = (xml) => {
  const out = new Map();
  for (const p of blocks(xml, 'properties')) for (const m of p.matchAll(/<([A-Za-z0-9_.-]+)(?:\s[^>]*)?>([\s\S]*?)<\/\1>/g)) out.set(m[1], clean(m[2]));
  return out;
};

/** One POM read on its own: identity, properties, management, dependencies (active-by-default profiles included). */
export function parsePomText(text) {
  const xml = text.replace(/<!--[\s\S]*?-->/g, '');
  const parent = blocks(xml, 'parent')[0] ?? '';
  const profiles = blocks(blocks(xml, 'profiles')[0] ?? '', 'profile');
  const active = profiles.filter((p) => tag(p, 'activeByDefault') === 'true');
  const inactiveDeps = profiles.filter((p) => !active.includes(p)).reduce((n, p) => n + blocks(blocks(without(p, ['dependencyManagement', 'build']), 'dependencies')[0] ?? '', 'dependency').length, 0);
  const top = without(xml, ['parent', 'build', 'profiles', 'reporting', 'pluginRepositories', 'repositories', 'distributionManagement']);
  const head = without(top, ['dependencies', 'dependencyManagement', 'properties', 'modules', 'licenses', 'developers', 'contributors', 'scm', 'organization', 'issueManagement', 'ciManagement', 'mailingLists']);
  const properties = props(top);
  for (const p of active) for (const [k, v] of props(p)) properties.set(k, v);
  const mgmt = (x) => blocks(blocks(x, 'dependencyManagement')[0] ?? '', 'dependency');
  const deps = (x) => blocks(blocks(without(x, ['dependencyManagement']), 'dependencies')[0] ?? '', 'dependency');
  const read = (d) => {
    const x = without(d, ['exclusions']);
    return { g: tag(x, 'groupId'), a: tag(x, 'artifactId'), v: tag(x, 'version'), scope: tag(x, 'scope') ?? 'compile', optional: tag(x, 'optional') === 'true', type: tag(x, 'type') };
  };
  return {
    groupId: tag(head, 'groupId') ?? tag(parent, 'groupId'), artifactId: tag(head, 'artifactId'), version: tag(head, 'version') ?? tag(parent, 'version'),
    parent: parent ? { g: tag(parent, 'groupId'), a: tag(parent, 'artifactId'), v: tag(parent, 'version'), path: tag(parent, 'relativePath') } : null,
    properties, managed: [...mgmt(top), ...active.flatMap(mgmt)].map(read), dependencies: [...deps(top), ...active.flatMap(deps)].map(read), inactiveDeps,
  };
}

/**
 * A pom.xml, with its parents inside the repository (<relativePath>, by default ../pom.xml, when the
 * coordinates match): their properties and dependency management apply. Returns { components, unresolved,
 * notes }; unresolved are direct dependencies whose version only Maven can tell (a parent or a BOM outside
 * the repository).
 */
export async function readPomFile(path) {
  const chain = [];
  let p = resolve(path);
  for (let i = 0; i < 10; i++) {
    let text;
    try { text = await readFile(p, 'utf8'); } catch { break; }
    const pom = parsePomText(text);
    if (chain.length) {
      const child = chain[chain.length - 1].parent;
      if (!child || pom.artifactId !== child.a || (pom.groupId && child.g && pom.groupId !== child.g)) break;
    }
    chain.push(pom);
    if (!pom.parent || pom.parent.path === '') break;
    const rel = pom.parent.path ?? '../pom.xml';
    p = resolve(dirname(p), rel.endsWith('.xml') ? rel : join(rel, 'pom.xml'));
  }
  const self = chain[0];
  const properties = new Map();
  for (const pom of [...chain].reverse()) for (const [k, v] of pom.properties) properties.set(k, v);
  for (const [k, v] of [['project.groupId', self.groupId], ['pom.groupId', self.groupId], ['project.version', self.version], ['pom.version', self.version], ['project.artifactId', self.artifactId], ['project.parent.version', self.parent?.v], ['parent.version', self.parent?.v]]) if (v) properties.set(k, v);
  const expand = (s) => { let x = s; for (let i = 0; i < 10 && x && /\$\{/.test(x); i++) x = x.replace(/\$\{([^}]+)\}/g, (all, k) => properties.get(k) ?? all); return x; };
  const managed = new Map();
  for (const pom of [...chain].reverse()) for (const d of pom.managed) if (d.scope !== 'import' && d.g && d.a && d.v) managed.set(`${expand(d.g)}:${expand(d.a)}`, expand(d.v));
  const components = [];
  const unresolved = [];
  const notes = [];
  // Modules of the same build (any POM of the parent chain shares the group): the product itself.
  const ownGroups = new Set(chain.map((c) => c.groupId).filter(Boolean));
  for (const d of self.dependencies) {
    const g = expand(d.g);
    const a = expand(d.a);
    if (!g || !a || d.scope === 'import') continue;
    let v = expand(d.v) ?? managed.get(`${g}:${a}`) ?? null;
    if (v) v = v.replace(/^\[([^,\]]+)\]$/, '$1'); // "[1.2.3]" is an exact version
    if (d.scope === 'system') notes.push(`${g}:${a} is a local file (scope system)`);
    if (!v || /\$\{|[[\](),]/.test(v)) { unresolved.push(`${g}:${a}`); continue; }
    if (ownGroups.has(g) && (v === self.version || d.v === '${project.version}')) continue;
    components.push(comp(`${g}:${a}`, v, { direct: true, scope: d.scope === 'test' || d.scope === 'provided' ? 'dev' : d.optional ? 'optional' : 'required' }));
  }
  if (self.inactiveDeps) notes.push(`${self.inactiveDeps} dependenc${self.inactiveDeps > 1 ? 'ies' : 'y'} in profiles not active by default left out`);
  return { components, unresolved, notes };
}

/** Folders whose pom.xml files are not the product's build: tests of Maven plugins, templates, unpacked jars. */
export const POM_NOT_BUILD = /(?:^|\/)(?:src\/(?:test|it|main\/resources)|META-INF|[^/]*-resources|archetype-resources|src\/site)\//;

export async function parsePomFile(path) {
  const { components, unresolved, notes } = await readPomFile(path);
  const out = [...components];
  const parts = ['lists the direct dependencies only (for the full tree, pass an SBOM from the CycloneDX Maven plugin)'];
  if (unresolved.length) parts.push(`${unresolved.length} direct dependenc${unresolved.length > 1 ? 'ies have' : 'y has'} no version Provetry can resolve here (a parent POM or a BOM outside the repository): ${unresolved.slice(0, 3).join(', ')}${unresolved.length > 3 ? '…' : ''}`);
  parts.push(...notes);
  Object.defineProperty(out, 'notice', { value: { text: parts.join('; '), missing: unresolved.length }, enumerable: false });
  return out;
}

export const _test = { basename };
