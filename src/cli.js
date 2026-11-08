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
import { reach } from './reach.js';
import { endOfLife } from './vuln/eol.js';
import { toText, toMarkdown, toJson, toSarif, clockText } from './report.js';
import { defaultContext } from './net.js';
import { VERSION } from './version.js';

const HELP = `provetry ${VERSION}: SBOM and vulnerability watch for the EU Cyber Resilience Act

Usage
  provetry sbom  [dir]            Write an SBOM from the lock files found in dir (default: .)
  provetry scan  [dir|sbom.json]  List known vulnerabilities, those exploited in the wild first
  provetry reach [dir]            Which vulnerabilities are really called by your code (Go, with govulncheck)
  provetry eol   [dir|sbom.json]  Components whose support ends, before your own support period does
  provetry clock --since <date>   Article 14 reporting deadlines from the moment you became aware

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

eol options
  --support-until <date>    end of your product's support period (YYYY-MM-DD): flags earlier ends
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
    const { components, files, errors } = await collect(abs);
    for (const e of errors) process.stderr.write(`provetry: ${clean(e.error)}\n`);
    if (!files.length) fail(`no supported lock file found in ${target} (run "provetry --help" for the list, or pass an SBOM)`);
    const unknownDirect = [...new Set(components.filter((c) => typeof c.direct !== 'boolean').flatMap((c) => c.sources))];
    // Paths in reports are relative to where you run the command, so code-scanning tools can find the files.
    const rel = (f) => relative(process.cwd(), join(abs, f)) || f;
    for (const c of components) c.sources = c.sources.map(rel);
    return { components, name: basename(abs), version: '', location: rel(files[0]), errors, unknownDirect: unknownDirect.map(rel) };
  }
  let json;
  try {
    json = JSON.parse(await readFile(abs, 'utf8'));
  } catch {
    fail(`${target} is not a JSON file`);
  }
  const s = readSbom(json);
  return { components: s.components, name: s.name || basename(abs), version: s.version, location: relative(process.cwd(), abs) || basename(abs), errors: [], unknownDirect: [] };
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
    const { components, name, errors, unknownDirect } = await loadComponents(dir);
    if (errors.length) fail('no SBOM written: fix the lock files above first, an SBOM must not miss components');
    if (unknownDirect.length) process.stderr.write(`provetry: no manifest says which dependencies are direct for ${unknownDirect.join(', ')}: their top-level dependencies cannot be told apart from the others in the SBOM\n`);
    const product = { name: values.name ?? name, version: values.version, supplier: values.supplier };
    const doc = values.format === 'spdx' ? toSpdx(product, components) : toCycloneDx(product, components);
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
    const { components, name, version, location, errors } = await loadComponents(target);
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
    else if (!result.sources.find((s) => s.name === 'OSV.dev')?.ok || errors.length || (gate && !result.complete)) process.exitCode = 2;
    return;
  }

  if (cmd === 'reach') {
    const { values, positionals } = parseArgs({
      args: rest,
      allowPositionals: true,
      options: { out: { type: 'string' }, product: { type: 'string' }, govulncheck: { type: 'string', default: 'govulncheck' } },
    });
    const dir = resolve(positionals[0] ?? '.');
    const st = await stat(dir).catch(() => null);
    if (!st?.isDirectory()) fail(`${positionals[0] ?? '.'} is not a directory`);
    const product = values.product ?? `pkg:generic/${encodeURIComponent(basename(dir))}`;
    let r;
    try {
      r = await reach(dir, { govulncheck: values.govulncheck, product });
    } catch (e) {
      fail(e.message);
    }
    if (!r.modules.length) fail('no go.mod found: reachability is available for Go modules (other ecosystems have no tool of that precision yet)');
    for (const e of r.errors) process.stderr.write(`provetry: govulncheck failed in ${clean(e.module)}: ${clean(e.error)}\n`);
    await emit(JSON.stringify(r.doc, null, 2) + '\n', values.out);
    const n = (s) => r.doc.statements.filter((x) => x.status === s).length;
    process.stderr.write(`provetry: ${r.modules.length} Go module${r.modules.length > 1 ? 's' : ''} checked: ${n('affected')} vulnerable function${n('affected') === 1 ? '' : 's'} called, ${n('not_affected')} not called\n`);
    if (r.errors.length) process.exitCode = 2;
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
    if (!until) out.push('', 'Add --support-until <date> to flag components whose support ends before yours.');
    process.stdout.write(out.join('\n') + '\n');
    if (r.results.some((x) => x.isEol || x.beforeSupportEnd)) process.exitCode = 1;
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
