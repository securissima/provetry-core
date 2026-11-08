#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
import { parseArgs } from 'node:util';
import { readFile, writeFile, stat } from 'node:fs/promises';
import { resolve, basename, relative, join } from 'node:path';
import { collect } from './lockfiles/index.js';
import { readSbom } from './sbom/read.js';
import { toCycloneDx, toSpdx } from './sbom/write.js';
import { scan, reachesThreshold } from './scan.js';
import { readVex, vexTemplate } from './vex.js';
import { reportingClock } from './clock.js';
import { reach, goModules, mergeReach, fromUsage } from './reach.js';
import { usage } from './usage/index.js';
import { rustFunctions } from './usage/rust.js';
import { endOfLife } from './vuln/eol.js';
import { verifyChain, verifyTimestamps, readCertificates, lateCoverage } from './journal.js';
import { toText, toMarkdown, toJson, toSarif, clockText } from './report.js';
import { defaultContext } from './net.js';
import { VERSION } from './version.js';

const HELP = `provetry ${VERSION}: SBOM and vulnerability watch for the EU Cyber Resilience Act

Usage
  provetry sbom  [dir]            Write an SBOM from the lock files found in dir (default: .)
  provetry scan  [dir|sbom.json]  List known vulnerabilities, those exploited in the wild first
  provetry reach [dir]            Which vulnerable code your product really uses: function by function for Go
                                  (govulncheck), package by package for npm, PyPI, Cargo, Composer, RubyGems, NuGet, Java
  provetry eol   [dir|sbom.json]  Components whose support ends, before your own support period does
  provetry clock --since <date>   Article 14 reporting deadlines from the moment you became aware
  provetry verify-journal <file> [--head <hash>] [--tsa-ca <pem>]  Check an evidence journal exported from Provetry (hash chain, timestamps)

sbom options
  --format cyclonedx|spdx   default cyclonedx
  --name <name>             product name (default: the directory name)
  --version <version>       product version
  --supplier <name>         your company, as it should appear in the SBOM
  --out <file>              write to a file instead of standard output

scan options
  --format text|markdown|json|sarif   default text
  --out <file>              write the report to a file
  --vex <file>              your VEX statements (OpenVEX or CycloneDX); repeatable
  --vex-template <file>     also write an OpenVEX file to fill in, one statement per finding
  --fail-on <level>         exit 1 if a finding reaches: exploited|critical|high|medium|low|any
  --include-dev             also scan development dependencies
  --no-euvd                 skip the ENISA EUVD lookup
  --no-epss                 skip the FIRST EPSS lookup (likelihood of exploitation, used to sort)
  --offline                 use cached data only, make no network request
  --no-cache                neither read nor write the cache

reach options
  --out <file>              write the OpenVEX document to a file (default: standard output)
  --product <purl>          how the document names your product (default: pkg:generic/<dir name>)
  --govulncheck <path>      the govulncheck binary (default: govulncheck on the PATH)
  --no-imports              Go only: skip the import analysis of the other ecosystems
  --gate <file>             also write the statements a CI gate may rely on (govulncheck's only; the
                            import analysis suggests, it does not decide), for scan --vex
  --offline, --no-cache     as for scan (the import analysis looks the vulnerabilities up)

eol options
  --support-until <date>    end of your product's support period (YYYY-MM-DD): flags earlier ends
                            (exit code 1 when a component is unsupported or ends earlier)
  --json                    machine-readable output
  --offline, --no-cache     as for scan

clock options
  --since <date>            when you became aware (ISO 8601, e.g. 2026-11-07T09:30:00Z)
  --incident                severe incident rather than an exploited vulnerability
  --fix <date>              when the corrective measure became available (final report date)
  --notified <date>         for an incident: when you submitted the notification
  --json                    machine-readable output

Exit codes: 0 done, 1 --fail-on threshold reached, 2 error or incomplete data
(with --fail-on, a scan that could not check every source exits 2 rather than pass).
Docs: https://github.com/Enigmacker/provetry-core
`;

// Text from files and advisories goes to the terminal: no control characters.
const clean = (s) => String(s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]+/g, ' ');

function fail(msg) {
  process.stderr.write(`provetry: ${clean(msg)}\n`);
  process.exit(2);
}

async function emit(text, out) {
  if (out) await writeFile(out, text);
  else process.stdout.write(text);
}

async function loadComponents(target) {
  const abs = resolve(target);
  const st = await stat(abs).catch(() => fail(`not found: ${target}`));
  if (st.isDirectory()) {
    const { components, files, errors, notices } = await collect(abs);
    for (const e of errors) process.stderr.write(`provetry: ${clean(e.error)}\n`);
    for (const n of notices ?? []) process.stderr.write(`provetry: note: ${clean(n.text)}\n`);
    if (!files.length) fail(`no supported lock file found in ${target} (run "provetry --help" for the list, or pass an SBOM)`);
    const unknownDirect = [...new Set(components.filter((c) => typeof c.direct !== 'boolean').flatMap((c) => c.sources))];
    // Paths in reports are relative to where you run the command, so code-scanning tools can find the files.
    const rel = (f) => relative(process.cwd(), join(abs, f)) || f;
    for (const c of components) c.sources = c.sources.map(rel);
    return { components, name: basename(abs), version: '', location: rel(files[0]), errors, unknownDirect: unknownDirect.map(rel), notices: notices ?? [] };
  }
  let json;
  try {
    json = JSON.parse(await readFile(abs, 'utf8'));
  } catch {
    fail(`${target} is not a JSON file`);
  }
  const s = readSbom(json);
  for (const n of s.notices ?? []) process.stderr.write(`provetry: note: ${clean(n.text)}\n`);
  return { components: s.components, name: s.name || basename(abs), version: s.version, location: relative(process.cwd(), abs) || basename(abs), errors: [], unknownDirect: [], notices: s.notices ?? [] };
}

function parseDate(s, flag) {
  const d = new Date(s);
  if (!s || Number.isNaN(d.getTime())) fail(`${flag} needs a date, for example 2026-11-07T09:30:00Z`);
  return d;
}

export async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') return void process.stdout.write(HELP);
  if (cmd === '--version' || cmd === '-v') return void process.stdout.write(`${VERSION}\n`);

  if (cmd === 'sbom') {
    const { values, positionals } = parseArgs({
      args: rest,
      allowPositionals: true,
      options: { format: { type: 'string', default: 'cyclonedx' }, name: { type: 'string' }, version: { type: 'string' }, supplier: { type: 'string' }, out: { type: 'string' } },
    });
    if (!['cyclonedx', 'spdx'].includes(values.format)) fail('--format must be cyclonedx or spdx');
    const dir = positionals[0] ?? '.';
    const st = await stat(resolve(dir)).catch(() => null);
    if (!st?.isDirectory()) fail(`${dir} is not a directory`);
    const { components, name, errors, unknownDirect, notices } = await loadComponents(dir);
    if (errors.length) fail('no SBOM written: fix the lock files above first, an SBOM must not miss components');
    if (unknownDirect.length) process.stderr.write(`provetry: no manifest says which dependencies are direct for ${unknownDirect.join(', ')}: their top-level dependencies cannot be told apart from the others in the SBOM\n`);
    const product = { name: values.name ?? name, version: values.version, supplier: values.supplier };
    // What the files could not give (Maven's transitive tree, unresolved versions) is written in the SBOM too.
    const incomplete = notices.map((n) => n.text);
    const unresolved = notices.reduce((s, n) => s + (n.missing ?? 0), 0);
    const doc = values.format === 'spdx' ? toSpdx(product, components, { incomplete, unresolved }) : toCycloneDx(product, components, { incomplete, unresolved });
    await emit(JSON.stringify(doc, null, 2) + '\n', values.out);
    if (values.out) process.stderr.write(`provetry: ${components.length} components written to ${values.out}\n`);
    return;
  }

  if (cmd === 'scan') {
    const { values, positionals } = parseArgs({
      args: rest,
      allowPositionals: true,
      options: {
        format: { type: 'string', default: 'text' },
        out: { type: 'string' },
        vex: { type: 'string', multiple: true, default: [] },
        'vex-template': { type: 'string' },
        'fail-on': { type: 'string' },
        'include-dev': { type: 'boolean', default: false },
        'no-euvd': { type: 'boolean', default: false },
        'no-epss': { type: 'boolean', default: false },
        offline: { type: 'boolean', default: false },
        'no-cache': { type: 'boolean', default: false },
        name: { type: 'string' },
        version: { type: 'string' },
      },
    });
    const fmt = { text: toText, markdown: toMarkdown, json: toJson, sarif: toSarif }[values.format];
    if (!fmt) fail('--format must be text, markdown, json or sarif');
    if (values['fail-on'] && !['exploited', 'critical', 'high', 'medium', 'low', 'any', 'none'].includes(values['fail-on'])) fail('--fail-on must be exploited, critical, high, medium, low or any');
    if (values.offline && values['no-cache']) fail('--offline needs the cache');
    const target = positionals[0] ?? '.';
    const { components, name, version, location, errors, notices } = await loadComponents(target);
    const vex = [];
    for (const f of values.vex) {
      try {
        vex.push(...readVex(JSON.parse(await readFile(f, 'utf8'))));
      } catch (e) {
        fail(`cannot read VEX file ${f}: ${e.message}`);
      }
    }
    const ctx = await defaultContext({ cache: !values['no-cache'] });
    ctx.offline = values.offline;
    const result = await scan(ctx, components, {
      product: { name: values.name ?? name, ...(values.version ?? version ? { version: values.version ?? version } : {}) },
      vex,
      includeDev: values['include-dev'],
      euvd: !values['no-euvd'],
      epss: !values['no-epss'],
    });
    if (notices.length) result.notes = notices.map((n) => n.text);
    // Direct dependencies without a version: below the minimum the CRA asks of an SBOM, so incomplete.
    if (notices.some((n) => n.missing)) {
      result.complete = false;
      result.sources.push({ name: 'Maven pom.xml', ok: false, note: `${notices.reduce((s, n) => s + n.missing, 0)} direct dependencies without a resolvable version` });
    }
    if (errors.length) {
      result.complete = false;
      result.sources.push({ name: 'Lock files', ok: false, note: `${errors.length} could not be read` });
    }
    const text = values.format === 'sarif' ? JSON.stringify(toSarif(result, { location }), null, 2) + '\n' : fmt(result);
    await emit(text, values.out);
    if (values['vex-template']) await writeFile(values['vex-template'], JSON.stringify(vexTemplate(result.findings), null, 2) + '\n');
    // A gate must not pass on missing data: incomplete results exit 2, unless a finding already fails the gate.
    const gate = values['fail-on'] && values['fail-on'] !== 'none';
    if (reachesThreshold(result, values['fail-on'])) process.exitCode = 1;
    else if (!result.sources.find((s) => s.name === 'OSV.dev')?.ok || errors.length || (gate && !result.complete)) {
      process.exitCode = 2;
      if (gate && notices.some((n) => n.missing)) process.stderr.write('provetry: direct Maven dependencies have no version Provetry can resolve, so the gate cannot pass on this data: pass an SBOM from the CycloneDX Maven plugin (complete tree), or run without --fail-on\n');
    }
    return;
  }

  if (cmd === 'reach') {
    const { values, positionals } = parseArgs({
      args: rest,
      allowPositionals: true,
      options: { out: { type: 'string' }, product: { type: 'string' }, govulncheck: { type: 'string', default: 'govulncheck' }, 'no-imports': { type: 'boolean', default: false }, gate: { type: 'string' }, offline: { type: 'boolean', default: false }, 'no-cache': { type: 'boolean', default: false } },
    });
    if (values.offline && values['no-cache']) fail('--offline needs the cache');
    const dir = resolve(positionals[0] ?? '.');
    const st = await stat(dir).catch(() => null);
    if (!st?.isDirectory()) fail(`${positionals[0] ?? '.'} is not a directory`);
    const product = values.product ?? `pkg:generic/${encodeURIComponent(basename(dir))}`;
    const lists = [];
    const tools = [];
    let goStatements = [];
    let incomplete = false;
    const summary = [];

    // Go: govulncheck, function by function.
    const goMods = await goModules(dir);
    if (goMods.length) {
      try {
        const r = await reach(dir, { govulncheck: values.govulncheck, product });
        for (const e of r.errors) process.stderr.write(`provetry: govulncheck failed in ${clean(e.module)}: ${clean(e.error)}\n`);
        if (r.errors.length) incomplete = true;
        goStatements = r.doc.statements.map((x) => ({ vulnerability: x.vulnerability, purl: x.products[0].subcomponents[0]['@id'], status: x.status, justification: x.justification, status_notes: x.impact_statement ?? x.status_notes }));
        lists.push(goStatements);
        tools.push('govulncheck');
        const n = (s) => r.doc.statements.filter((x) => x.status === s).length;
        summary.push(`${r.modules.length} Go module${r.modules.length > 1 ? 's' : ''}: ${n('affected')} vulnerable function${n('affected') === 1 ? '' : 's'} called, ${n('not_affected')} not called`);
      } catch (e) {
        process.stderr.write(`provetry: ${clean(e.message)}\n`);
        incomplete = true;
      }
    }

    // Every other ecosystem: is the vulnerable package loaded at all?
    if (!values['no-imports']) {
      const u = await usage(dir);
      for (const e of u.errors) process.stderr.write(`provetry: ${clean(e.file)}: ${clean(e.error)}\n`);
      if (u.errors.length) incomplete = true;
      if (u.projects.length) {
        const collected = await collect(dir);
        for (const n of collected.notices ?? []) process.stderr.write(`provetry: note: ${clean(n.text)}\n`);
        const comps = collected.components.filter((c) => c.type !== 'golang');
        const ctx = await defaultContext({ cache: !values['no-cache'] });
        ctx.offline = values.offline;
        const r = await scan(ctx, comps, { includeDev: true, epss: false });
        if (!r.complete) { incomplete = true; process.stderr.write('provetry: some vulnerability sources did not answer: the result may be incomplete\n'); }
        const all = [...r.findings, ...r.suppressed];
        const statements = fromUsage(all, u.components, { functions: await rustFunctions(dir, all, u.components) });
        lists.push(statements);
        tools.push('import analysis');
        const n = (s) => statements.filter((x) => x.status === s).length;
        summary.push(`${u.projects.length} lock file${u.projects.length > 1 ? 's' : ''}: ${n('not_affected')} vulnerable package${n('not_affected') === 1 ? '' : 's'} never loaded, ${n('under_investigation')} loaded`);
      }
    }
    if (!lists.length) fail('nothing to analyse: no go.mod and no lock file with a dependency graph (package-lock.json, pnpm-lock.yaml, yarn.lock, Cargo.lock, poetry.lock, uv.lock, composer.lock, Gemfile.lock, packages.lock.json, gradle.lockfile, pom.xml, requirements.txt from pip-compile)');
    const doc = mergeReach(lists, { product, tools });
    await emit(JSON.stringify(doc, null, 2) + '\n', values.out);
    // The statements a CI gate may rely on: govulncheck's (function level). The import analysis only
    // suggests; its "not affected" waits for the manufacturer's decision.
    if (values.gate) await writeFile(values.gate, JSON.stringify(mergeReach([goStatements], { product, tools: ['govulncheck'] }), null, 2) + '\n');
    process.stderr.write(`provetry: ${summary.join('; ')}\n`);
    if (incomplete) process.exitCode = 2;
    return;
  }

  if (cmd === 'eol') {
    const { values, positionals } = parseArgs({
      args: rest,
      allowPositionals: true,
      options: { 'support-until': { type: 'string' }, json: { type: 'boolean', default: false }, offline: { type: 'boolean', default: false }, 'no-cache': { type: 'boolean', default: false }, 'include-dev': { type: 'boolean', default: false } },
    });
    const until = values['support-until'];
    if (until && !/^\d{4}-\d{2}-\d{2}$/.test(until)) fail('--support-until needs a date, for example 2031-12-31');
    if (values.offline && values['no-cache']) fail('--offline needs the cache');
    const { components } = await loadComponents(positionals[0] ?? '.');
    const ctx = await defaultContext({ cache: !values['no-cache'] });
    ctx.offline = values.offline;
    let r;
    try {
      r = await endOfLife(ctx, components.filter((c) => values['include-dev'] || c.scope !== 'dev'), { supportUntil: until ?? null });
    } catch (e) {
      fail(`endoflife.date unavailable (${e.code ?? e.message})`);
    }
    if (values.json) return void process.stdout.write(JSON.stringify(r, null, 2) + '\n');
    const out = [`${r.known} of ${r.checked} components have a published support policy on endoflife.date.`, ''];
    for (const x of r.results) {
      const when = x.eolFrom ? (x.isEol ? `support ended ${x.eolFrom}` : `support ends ${x.eolFrom}`) : x.isEol ? 'no longer supported' : 'end of support not announced';
      out.push(clean(`${x.isEol ? '!! ' : x.beforeSupportEnd ? '!  ' : '   '}${x.name}@${x.version}  ${x.label} ${x.cycle}: ${when}${x.beforeSupportEnd && !x.isEol ? ', before your own support period ends' : ''}${x.latest ? ` (latest ${x.latest})` : ''}`));
    }
    if (!r.results.length) out.push('Nothing to report for the components it knows.');
    if (r.failed.length) out.push('', `! Not checked this time (endoflife.date did not answer): ${r.failed.join(', ')}.`);
    if (!until) out.push('', 'Add --support-until <date> to flag components whose support ends before yours.');
    process.stdout.write(out.join('\n') + '\n');
    if (r.results.some((x) => x.isEol || x.beforeSupportEnd)) process.exitCode = 1;
    else if (r.failed.length) process.exitCode = 2;
    return;
  }

  if (cmd === 'verify-journal') {
    const { values, positionals } = parseArgs({ args: rest, allowPositionals: true, options: { head: { type: 'string', multiple: true, default: [] }, 'tsa-ca': { type: 'string', multiple: true, default: [] } } });
    const file = positionals[0];
    if (!file) fail('give the exported journal: provetry verify-journal <file>');
    let doc;
    try { doc = JSON.parse(await readFile(file, 'utf8')); } catch { fail(`${file} is not a JSON file`); }
    if (doc?.format !== 'provetry-evidence-journal' || !Array.isArray(doc.entries)) fail(`${file} is not a Provetry evidence journal`);
    const broken = verifyChain(doc.entries);
    if (broken) {
      process.stdout.write(`BROKEN at entry ${broken.seq}: ${broken.reason}.\n`);
      process.exitCode = 1;
      return;
    }
    const ts = Array.isArray(doc.timestamps) ? doc.timestamps : [];
    // The authority's CA certificates: without them a token proves its signature, not who signed it.
    let trust;
    if (values['tsa-ca'].length) {
      trust = [];
      for (const f of values['tsa-ca']) { try { trust.push(...readCertificates(await readFile(f, 'utf8'))); } catch { fail(`${f} could not be read`); } }
      if (!trust.length) fail('--tsa-ca: no certificate found');
    }
    const tsCheck = verifyTimestamps(doc.entries, ts, { trust });
    if (tsCheck.broken) {
      process.stdout.write(`BROKEN at entry ${tsCheck.broken.seq}: ${tsCheck.broken.reason}.\n`);
      process.exitCode = 1;
      return;
    }
    // A hash kept earlier (from a dossier, an e-mail, an earlier export) must still be in the chain:
    // otherwise the history was cut or rewritten since, even if the new chain is consistent.
    for (const h of values.head) {
      if (!doc.entries.some((e) => e.hash === h.trim().toLowerCase())) {
        process.stdout.write(`BROKEN: the hash ${h} kept earlier is not in this journal: its history was cut or rewritten since.\n`);
        process.exitCode = 1;
        return;
      }
    }
    const head = doc.entries.at(-1)?.hash ?? '(empty)';
    process.stdout.write(`OK: ${doc.entries.length} entr${doc.entries.length === 1 ? 'y' : 'ies'}, chain intact${values.head.length ? `, ${values.head.length} kept hash${values.head.length > 1 ? 'es' : ''} found` : ''}.\nLatest hash: ${head}\n`);
    if (tsCheck.checked.length) {
      const last = tsCheck.checked.reduce((a, b) => (b.seq > a.seq ? b : a));
      const n = tsCheck.checked.length;
      process.stdout.write(`${n} outside timestamp${n > 1 ? 's' : ''} (RFC 3161) match the chain, signature${n > 1 ? 's' : ''} valid; the latest covers entry ${last.seq} at ${last.genTime}, signed by ${last.signer}.\n`);
      if (trust) process.stdout.write('The signing certificates chain to the authority certificate given (--tsa-ca).\n');
      else process.stdout.write(`Who signed is not checked: give the authority's CA certificate with --tsa-ca <file> (or: openssl ts -verify -digest ${ts.find((t) => Number(t.seq) === last.seq).hash} -in <token> -CAfile <its CA certificate>).\n`);
    }
    for (const l of lateCoverage(doc.entries, tsCheck.checked)) {
      process.stdout.write(`Note: entr${l.from === l.to ? `y ${l.from} was` : `ies ${l.from}-${l.to} were`} first timestamped on ${l.stampedAt}, more than two days after the time given: written, or rewritten, later than it says.\n`);
    }
    // Tokens prove when the latest entries existed, not that the history before the oldest token is older.
    if (!values.head.length) process.stdout.write('Without a hash kept outside the service (--head), a journal rewritten from the start, then timestamped again, would also pass.\n');
    if (doc.head && doc.head !== head) process.stdout.write('Note: the "head" field of the file does not match its last entry.\n');
    return;
  }

  if (cmd === 'clock') {
    const { values } = parseArgs({ args: rest, options: { since: { type: 'string' }, incident: { type: 'boolean', default: false }, fix: { type: 'string' }, notified: { type: 'string' }, json: { type: 'boolean', default: false } } });
    const awareAt = parseDate(values.since, '--since');
    const fixAt = values.fix ? parseDate(values.fix, '--fix') : null;
    const notifiedAt = values.notified ? parseDate(values.notified, '--notified') : null;
    if (values.incident && fixAt) fail('--fix applies to vulnerabilities, not incidents');
    if (!values.incident && notifiedAt) fail('--notified applies to incidents (--incident)');
    if (fixAt && fixAt < awareAt) fail('--fix is before --since');
    if (notifiedAt && notifiedAt < awareAt) fail('--notified is before --since');
    if (awareAt < new Date('2026-09-11T00:00:00Z')) process.stderr.write('provetry: note: Article 14 applies from 11 September 2026; this date is earlier\n');
    const now = new Date();
    const c = reportingClock({ kind: values.incident ? 'incident' : 'vulnerability', awareAt, fixAt, notifiedAt, now });
    if (values.json) return void process.stdout.write(JSON.stringify(c, null, 2) + '\n');
    return void process.stdout.write(clockText(c, now));
  }

  fail(`unknown command "${cmd}" (try provetry --help)`);
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${resolve(process.argv[1])}`).href;
if (isMain || basename(process.argv[1] ?? '') === 'provetry') {
  main(process.argv.slice(2)).catch((e) => fail(e.message));
}
