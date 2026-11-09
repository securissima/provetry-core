// SPDX-License-Identifier: AGPL-3.0-only
// Reachability: is the vulnerable code actually called by your product? A known vulnerability in a
// dependency is often harmless because the function at fault is never used. For Go, the Go team's
// govulncheck answers this precisely: it builds the call graph of your code and reports, for each
// vulnerability, whether it is only required, imported, or really called.
//
// `provetry reach` runs govulncheck in every Go module of the repository and turns its answer into one
// OpenVEX document: "not_affected" (vulnerable_code_not_in_execute_path, or not_present) for what is never
// called, "affected" for what is. Pass it to `provetry scan --vex` and the noise goes; keep it in your
// repository and it documents why. It runs where your code and your Go toolchain are (your machine, your
// CI): nothing is sent anywhere.
//
// Other ecosystems (npm, PyPI, Cargo, Composer, RubyGems, NuGet) get the import analysis of ./usage/: is
// the vulnerable package loaded by the code at all? Not loaded: "not_affected" with the chain that brings
// it in as evidence. Loaded: "under_investigation", with the file that imports it; whether the vulnerable
// function is called is not known at that level. Where the analysis cannot tell, nothing is said.
import { spawn } from 'node:child_process';
import { dirname, join, relative, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { findLockFiles, parseGoMod } from './lockfiles/index.js';
import { makePurl, parsePurl, fullName } from './purl.js';
import { TOOL } from './version.js';

const RANK = { affected: 3, under_investigation: 2, not_affected: 1, fixed: 0 };

/**
 * Directories of the Go modules under root (each with a go.mod), skipping vendored and hidden folders, and
 * testdata (Go's own convention for fixtures that are not part of the product).
 */
export async function goModules(root) {
  return (await findLockFiles(root))
    .filter((f) => (f.endsWith('/go.mod') || f === 'go.mod') && !/(^|\/)testdata\//.test(f))
    .map((f) => dirname(resolve(root, f)));
}

/** Runs a command and returns { code, stdout, stderr }; never throws for a non-zero exit. */
export function run(cmd, args, { cwd, timeoutMs = 15 * 60_000, maxBytes = 64 * 1024 * 1024 } = {}) {
  return new Promise((resolvePromise, reject) => {
    let out = '';
    let err = '';
    const child = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => {
      out += d;
      if (out.length > maxBytes) child.kill('SIGKILL');
    });
    child.stderr.on('data', (d) => {
      err = (err + d).slice(-20_000);
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      reject(e.code === 'ENOENT' ? Object.assign(new Error(`${cmd} not found`), { code: 'ENOENT' }) : e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolvePromise({ code, stdout: out, stderr: err });
    });
  });
}

/** govulncheck writes Go module paths escaped (golang.org%2Fx%2Fnet): the same purl as Provetry's SBOM. */
export function canonicalPurl(purl) {
  const p = parsePurl(purl);
  if (!p) return purl;
  return makePurl(p.type, fullName(p), p.version ?? undefined);
}

/**
 * Statements of one govulncheck OpenVEX document, normalised: one per vulnerability and component, with
 * Provetry's purls, the module it was checked from, and the reason in plain words.
 */
export function fromGovulncheck(doc, { module = '.', version = '' } = {}) {
  const out = [];
  for (const s of doc?.statements ?? []) {
    const name = s.vulnerability?.name;
    if (!name || !s.status) continue;
    // The standard library is the one of the Go that ran govulncheck, not necessarily the one that builds
    // the product: its answer would be about another version, so it is left out.
    const subs = (s.products ?? []).flatMap((p) => p.subcomponents ?? []).map((c) => c['@id'])
      .filter((id) => typeof id === 'string' && id.startsWith('pkg:') && !/^pkg:golang\/stdlib@/.test(id));
    for (const purl of subs) {
      out.push({
        vulnerability: { name, ...(s.vulnerability.aliases?.length ? { aliases: s.vulnerability.aliases } : {}) },
        purl: canonicalPurl(purl),
        status: s.status,
        ...(s.justification ? { justification: s.justification } : {}),
        status_notes:
          s.status === 'not_affected'
            ? `govulncheck${version ? ` ${version}` : ''} found no call to the vulnerable code from the module in ${module}${s.justification === 'vulnerable_code_not_present' ? ' (the vulnerable package is not even imported)' : ''}, for the platform and build tags it ran with (calls through reflection, cgo or plugins are not seen).`
            : `govulncheck${version ? ` ${version}` : ''} found a call path to the vulnerable code from the module in ${module}.`,
      });
    }
  }
  return out;
}

/**
 * Merges the answers of several modules: a component is "not affected" only if no module calls the
 * vulnerable code. Returns an OpenVEX document about `product` (a purl or IRI naming your product).
 */
export function mergeReach(lists, { product = 'pkg:generic/product', now = new Date(), tools = ['govulncheck'] } = {}) {
  const byKey = new Map();
  for (const st of lists.flat()) {
    const key = `${st.vulnerability.name}|${st.purl}`;
    const prev = byKey.get(key);
    if (!prev || RANK[st.status] > RANK[prev.status]) byKey.set(key, st);
    else if (prev && RANK[st.status] === RANK[prev.status] && st.status === 'not_affected' && st.justification === 'vulnerable_code_not_in_execute_path') {
      // Imported somewhere but never called beats "not imported" as the description of the whole product.
      byKey.set(key, st);
    }
  }
  const ts = now.toISOString();
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `https://provetry.com/reach/${ts}`,
    author: `Provetry reachability (${tools.join(', ')})`,
    timestamp: ts,
    version: 1,
    tooling: [`${TOOL.name}/${TOOL.version}`, ...tools.filter((t) => t !== 'import analysis')].join(' + '),
    statements: [...byKey.values()]
      .sort((a, b) => a.vulnerability.name.localeCompare(b.vulnerability.name) || a.purl.localeCompare(b.purl))
      .map((st) => ({
        vulnerability: st.vulnerability,
        products: [{ '@id': product, subcomponents: [{ '@id': st.purl }] }],
        status: st.status,
        ...(st.justification ? { justification: st.justification } : {}),
        ...(st.status === 'not_affected' ? { impact_statement: st.status_notes } : { status_notes: st.status_notes }),
        ...(st.status === 'affected' ? { action_statement: 'Update the component to a fixed version, or stop calling the vulnerable code.' } : {}),
      })),
  };
}

/**
 * Runs govulncheck in every Go module under root. Returns { doc, modules, errors }.
 * `exec` is injectable for the tests.
 */
export async function reach(root, { govulncheck = 'govulncheck', product, exec = run, now } = {}) {
  const modules = await goModules(root);
  const errors = [];
  const lists = [];
  let version = '';
  try {
    const v = await exec(govulncheck, ['-version'], { cwd: root, timeoutMs: 30_000 });
    version = (/govulncheck@?\s*v?([\d.]+)/i.exec(v.stdout + v.stderr) ?? [])[1] ?? '';
  } catch (e) {
    if (e.code === 'ENOENT') throw Object.assign(new Error('govulncheck is not installed: go install golang.org/x/vuln/cmd/govulncheck@v1.1.4'), { code: 'NO_GOVULNCHECK' });
    throw e;
  }
  for (const dir of modules) {
    const label = relative(resolve(root), dir) || '.';
    const r = await exec(govulncheck, ['-format', 'openvex', './...'], { cwd: dir });
    let doc = null;
    try {
      doc = JSON.parse(r.stdout);
    } catch {
      doc = null;
    }
    if (!doc || r.code !== 0) {
      errors.push({ module: label, error: (r.stderr || 'govulncheck gave no OpenVEX output').trim().split('\n').slice(-3).join(' ') });
      continue;
    }
    lists.push(fromGovulncheck(doc, { module: label, version: version ? `v${version}` : '' }));
  }
  const merged = mergeReach(lists, { product, now });
  // A module that could not be checked may call what the others do not: nothing it depends on is
  // declared "not affected", only "under investigation".
  if (errors.length) {
    const unchecked = new Set();
    for (const e of errors) {
      try {
        for (const c of parseGoMod(await readFile(join(resolve(root), e.module, 'go.mod'), 'utf8'))) unchecked.add(c.purl);
      } catch {
        // Unreadable go.mod: nothing more to protect than what failed.
      }
    }
    for (const st of merged.statements) {
      const purl = st.products[0].subcomponents[0]['@id'];
      if (st.status === 'not_affected' && unchecked.has(purl)) {
        st.status = 'under_investigation';
        st.status_notes = `${st.impact_statement} Not concluded: another module that depends on it could not be checked.`;
        delete st.justification;
        delete st.impact_statement;
      }
    }
  }
  return { doc: merged, modules: modules.map((d) => relative(resolve(root), d) || '.'), errors };
}


const where = (ev = []) => ev.slice(0, 3).map((e) => `${e.file}:${e.line}`).join(', ');

/**
 * Statements from the import analysis (usage()) for the findings of a scan: one per vulnerability and
 * component, Go modules left to govulncheck. `found` is usage().components.
 */
export function fromUsage(findings, found, { version = TOOL.version, functions = new Map() } = {}) {
  const out = [];
  for (const f of findings) {
    const c = f.component;
    if (c.type === 'golang') continue;
    const u = found.get(c.purl);
    if (!u || u.state === 'unknown') continue;
    const vulnerability = { name: f.id, ...(f.ids.length > 1 ? { aliases: f.ids.slice(1) } : {}) };
    const by = `Provetry ${version} import analysis of ${u.project}`;
    if (u.state === 'not_loaded') {
      const via = u.chain.length > 1
        ? `It comes in through ${u.chain.join(' > ')}, and nothing in the project imports, names or runs ${u.chain[0]} or any package on the way.`
        : `It is in the lock file, but nothing in the project imports, names or runs it, and no package it loads depends on it.`;
      out.push({ vulnerability, purl: c.purl, status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path',
        status_notes: `${by}: ${c.name} is never loaded. ${via} A suggestion to check: the analysis does not see code that loads a package from a name built at run time, conventions of a framework that are not written in the repository, or code kept outside it.`,
        evidence: { state: 'not_loaded', chain: u.chain } });
    } else if (functions.get(`${f.id}|${c.purl}`)?.result === 'not_mentioned') {
      const fn = functions.get(`${f.id}|${c.purl}`);
      const which = fn.source ? `that lead to the fixed code (${fn.source})` : 'that the advisory names';
      out.push({ vulnerability, purl: c.purl, status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path',
        status_notes: `${by}: ${c.name} is used by the project's own code only (${where(u.evidence)}), and no file of the repository mentions the function${fn.names.length > 1 ? 's' : ''} ${which}: ${fn.names.join(', ')}. A suggestion to check: not seen are calls through callbacks, dynamic property access or another package's generic code.`,
        evidence: { state: 'not_called', functions: fn.names } });
    } else if (functions.get(`${f.id}|${c.purl}`)?.called) {
      const fn = functions.get(`${f.id}|${c.purl}`);
      const k = fn.called;
      out.push({ vulnerability, purl: c.purl, status: 'under_investigation',
        status_notes: `${by}: ${c.name} is imported, and the call analysis (${k.by}) finds a call of ${c.name}'s ${k.name} at ${k.file}:${k.line}, ${fn.source ? `a function that leads to the fixed code (${fn.source})` : 'an affected function the advisory names'}. The vulnerable code may be reached through this call: check it first.`,
        evidence: { state: 'called', file: k.file, line: k.line, function: k.name, mentioned: { file: fn.file, line: fn.line } } });
    } else if (functions.get(`${f.id}|${c.purl}`)?.result === 'mentioned') {
      const fn = functions.get(`${f.id}|${c.purl}`);
      out.push({ vulnerability, purl: c.purl, status: 'under_investigation',
        status_notes: `${by}: ${c.name} is imported, and ${fn.file}:${fn.line} mentions ${fn.name}, ${fn.source ? `a function that leads to the fixed code (${fn.source})` : 'an affected function the advisory names'}. Whether the vulnerable function itself is called is not known at this level: check this call first.`,
        evidence: { state: 'mentioned', file: fn.file, line: fn.line } });
    } else {
      const lead = u.state === 'imported' ? `${c.name} is ${u.evidence?.[0]?.how ?? 'imported'} in ${where(u.evidence)}` : `${c.name} is loaded through ${u.chain.join(' > ')} (${u.chain[0]}: ${where(u.evidence)})`;
      out.push({ vulnerability, purl: c.purl, status: 'under_investigation',
        status_notes: `${by}: ${lead}. Whether the vulnerable function itself is called is not known at this level.`,
        evidence: { state: u.state, ...(u.chain ? { chain: u.chain } : {}), files: (u.evidence ?? []).slice(0, 5) } });
    }
  }
  return out;
}
