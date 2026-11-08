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
// Other ecosystems have no tool of that precision yet; they are not guessed at.
import { spawn } from 'node:child_process';
import { dirname, relative, resolve } from 'node:path';
import { findLockFiles } from './lockfiles/index.js';
import { makePurl, parsePurl, fullName } from './purl.js';
import { TOOL } from './version.js';

const RANK = { affected: 3, under_investigation: 2, not_affected: 1, fixed: 0 };

/** Directories of the Go modules under root (each with a go.mod), skipping vendored and hidden folders. */
export async function goModules(root) {
  return (await findLockFiles(root)).filter((f) => f.endsWith('/go.mod') || f === 'go.mod').map((f) => dirname(resolve(root, f)));
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
    const subs = (s.products ?? []).flatMap((p) => p.subcomponents ?? []).map((c) => c['@id']).filter((id) => typeof id === 'string' && id.startsWith('pkg:'));
    for (const purl of subs) {
      out.push({
        vulnerability: { name, ...(s.vulnerability.aliases?.length ? { aliases: s.vulnerability.aliases } : {}) },
        purl: canonicalPurl(purl),
        status: s.status,
        ...(s.justification ? { justification: s.justification } : {}),
        status_notes:
          s.status === 'not_affected'
            ? `govulncheck${version ? ` ${version}` : ''} found no call to the vulnerable code from the module in ${module}${s.justification === 'vulnerable_code_not_present' ? ' (the vulnerable package is not even imported)' : ''}.`
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
export function mergeReach(lists, { product = 'pkg:generic/product', now = new Date() } = {}) {
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
    author: 'Provetry reachability (govulncheck)',
    timestamp: ts,
    version: 1,
    tooling: `${TOOL.name}/${TOOL.version} + govulncheck`,
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
    if (e.code === 'ENOENT') throw Object.assign(new Error('govulncheck is not installed: go install golang.org/x/vuln/cmd/govulncheck@latest'), { code: 'NO_GOVULNCHECK' });
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
  return { doc: mergeReach(lists, { product, now }), modules: modules.map((d) => relative(resolve(root), d) || '.'), errors };
}

