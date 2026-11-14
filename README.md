# Provetry

[![CI](https://github.com/Enigmacker/provetry-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Enigmacker/provetry-core/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

**A software bill of materials and a vulnerability watch for the EU Cyber Resilience Act, from the lock files you already have.**

Since 11 September 2026, manufacturers of products with digital elements sold in the EU must report actively exploited vulnerabilities within 24 hours (Article 14 of Regulation (EU) 2024/2847). From 11 December 2027, they must also keep an SBOM and handle vulnerabilities throughout the support period (Annex I, Part II). Provetry helps with the technical side of both:

- **`provetry sbom`** reads the lock files in your repository and writes a CycloneDX 1.6, SPDX 2.3 or SPDX 3.0.1 SBOM;
- **`provetry scan`** lists the known vulnerabilities in those components, **the ones exploited in the wild first** (CISA KEV and ENISA's EU Vulnerability Database), with the version that fixes each one, and takes your VEX statements into account;
- **`provetry reach`** tells which vulnerable code your product really uses: for Go, function by function (with the Go team's govulncheck); for npm, PyPI, Cargo, Composer, RubyGems, NuGet and Java, package by package (is it loaded at all?), and for Rust the affected functions RustSec names, with the evidence;
- **`provetry clock`** gives the Article 14 deadlines from the moment you became aware.

Free, open source, no account, no telemetry, no dependency. Node.js 22 or later.

> Provetry is a tool, not legal advice. It tells you what is in your product and what is known about it. Whether a vulnerability affects your product, and whether you must report it, remains your assessment.

---

## Contents

- [Quick start](#quick-start)
- [Supported lock files](#supported-lock-files)
- [SBOM](#sbom)
- [Vulnerability scan](#vulnerability-scan)
- [VEX: saying what does not affect you](#vex-saying-what-does-not-affect-you)
- [Reachability: is the vulnerable code used?](#reachability-is-the-vulnerable-code-used)
- [End of life of your components](#end-of-life-of-your-components)
- [Checking an evidence journal](#checking-an-evidence-journal)
- [Article 14 reporting clock](#article-14-reporting-clock)
- [Using it in CI](#using-it-in-ci)
- [Privacy: which services see what](#privacy-which-services-see-what)
- [Limitations](#limitations)
- [Library use](#library-use)
- [Development](#development)
- [License](#license)

---

## Quick start

```sh
npx github:Enigmacker/provetry-core sbom . --name my-product --version 2.4.0 --out sbom.cdx.json
npx github:Enigmacker/provetry-core scan .
```

Or clone and run `node src/cli.js` directly: there is nothing to install.

```text
Provetry 0.1.0 · my-product · 412 components scanned (138 development dependencies left out)

3 known vulnerabilities: 1 exploited in the wild · 0 critical · 1 high · 1 medium · 0 low

!! HIGH 7.5  CVE-2023-44487  golang.org/x/net@v0.15.0 (transitive)
   HTTP/2 rapid reset can cause excessive work in net/http
   exploited in the wild (CISA KEV since 2023-10-10; ENISA EUVD) · fixed in 0.17.0
   https://osv.dev/vulnerability/GO-2023-2102
...
```

## Supported lock files

| Ecosystem | Files |
|---|---|
| JavaScript | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` (lockfile v6 and v9; older ones are refused), `yarn.lock` (v1 and Berry) |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt` (pinned `==` lines only) |
| Go | `go.mod` (with `replace` directives) |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |
| .NET | `packages.lock.json` |
| Java, Kotlin, Scala | `gradle.lockfile`, `buildscript-gradle.lockfile` (Gradle dependency locking); `pom.xml` (direct dependencies only, see below) |

Provetry looks for them up to six directories deep, skipping `node_modules`, `vendor`, `.git` and similar, and merges what it finds: a monorepo with a Node front end and a Go back end gives one SBOM. Development dependencies are recognised where the lock file says so; they are marked in the SBOM and left out of the scan unless you ask.

Which dependencies are direct (the ones you asked for) comes from the lock file when it records it (npm, pnpm, Go, NuGet, Gemfile.lock), otherwise from the manifest next to it: `package.json` for Yarn, `Cargo.toml`, `composer.json`, `pyproject.toml` or `Pipfile` for Python, `build.gradle(.kts)` and the version catalog `gradle/libs.versions.toml` for Gradle. For `requirements.txt`, only pip-compile's `# via` comments tell; without them, Provetry says it cannot tell. For Go, the version in the `toolchain` directive is scanned too, since the standard library has advisories of its own (the `go` line is only a minimum, so it is not used).

A lock file that cannot be read stops `provetry sbom` (an SBOM must not silently miss components) and makes `provetry scan` exit 2.

Maven has no lock file: from `pom.xml`, Provetry reads the direct dependencies (the minimum the CRA asks of an SBOM), with the properties and `dependencyManagement` of the file and of its parents found in the repository, and of profiles active by default. It says what it could not resolve (versions set by a parent POM or an imported BOM outside the repository, which only Maven resolves), in the output, in the scan report (a scan with unresolved direct dependencies is incomplete) and in the SBOM itself (CycloneDX `compositions` marked `incomplete`, an SPDX comment, and a dependency relationship marked `incomplete` in SPDX 3). POMs of tests, templates and unpacked jars (`src/test`, `src/it`, `src/main/resources`, `META-INF`) are not read. With `--fail-on`, a scan with unresolved direct dependencies exits 2 (a gate does not pass on missing data, even through an SBOM written earlier, which keeps the information): for a Maven gate, pass the SBOM of the CycloneDX Maven plugin. For the full tree, add the [CycloneDX Maven plugin](https://github.com/CycloneDX/cyclonedx-maven-plugin) to the build and pass its SBOM. With Gradle, turn on [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html): `gradle.lockfile` lists every resolved component (the older `gradle/dependency-locks/*.lockfile` too). What ships is what is in a runtime classpath; test, compile-only, annotation-processor and linter configurations, debug-only variants (when release variants exist) and the build script are development dependencies.

### Container images and firmware

`provetry sbom` and `provetry scan` also read a container image or a firmware root filesystem, without running it:

```sh
docker save -o gateway.tar ghcr.io/acme/gateway:2.4.0     # or podman save; a Docker archive or an OCI layout
provetry sbom gateway.tar --out sbom.cdx.json
provetry sbom gateway.tar --platform linux/arm64          # a multi-platform image (default: linux/amd64)
provetry scan build/tmp/deploy/images/rootfs.tar.gz       # a firmware root filesystem (Yocto, Buildroot, debootstrap)
```

The archive may be compressed whole (gzip or zstd; zstd needs Node.js 22.15 or later). The layers are applied in order, with their whiteouts (files deleted by a later layer are not counted). Provetry reads:

- the operating system's packages: dpkg (Debian, Ubuntu, their derivatives, and distroless images' `status.d`), apk (Alpine, Wolfi, Chainguard) and opkg (OpenWrt, Yocto), with the release from `os-release`;
- packages installed by language package managers: Python distributions (`*.dist-info`, `*.egg-info`), Node.js packages (`node_modules`), and the lock files present in the image (not those in caches, documentation or test fixtures).

Debian, Ubuntu and Alpine packages are looked up on OSV.dev by release and source package (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.19`), Wolfi and Chainguard packages as such. A derivative (Raspberry Pi OS, Linux Mint) is looked up as the release it follows, which `os-release` names: its own packages are not covered. Nothing else of the image is kept in memory.

What Provetry cannot read is said, and the SBOM and the scan are marked incomplete (`scan --fail-on` then exits 2, never 0): RPM databases (Red Hat, Rocky, Alma, SUSE, Fedora), opkg packages and releases no public advisory database covers (Debian unstable, Alpine edge), a layer missing from the archive, several images in one archive. Save one image per archive.

For the rest (vendored C libraries, statically linked binaries, Java archives inside the image), generate an SBOM with your build tooling or with [Syft](https://github.com/anchore/syft) and pass it to `provetry scan`: CycloneDX JSON and SPDX JSON (2.x, and 3.x in JSON-LD) are read. In the GitHub Action, `image-tool: syft` keeps the generator used before 0.10 (it reads RPM databases, Java archives and Go binaries too, and needs an image name and Docker).

## SBOM

```sh
provetry sbom [dir | image.tar] [--format cyclonedx|spdx|spdx3] [--name <product>] [--version <v>] [--supplier <company>] [--out <file>] [--platform <os/arch>]
```

- Each component carries its [package URL](https://github.com/package-url/purl-spec) and, when the lock file has them, its hashes.
- The top-level dependencies of your product are listed as such in the dependency graph: the CRA asks for "at the very least the top-level dependencies" (Annex I, Part II, point 1). In CycloneDX they are the product's `dependsOn` list; in SPDX 2.3, `DEPENDS_ON` relationships from the product; in SPDX 3.0.1, a `dependsOn` relationship. When no lock file or manifest says which they are, Provetry leaves them out and tells you, rather than guessing.
- Development dependencies are kept but marked: `scope: excluded` in CycloneDX, `DEV_DEPENDENCY_OF` in SPDX 2.3, a `dependsOn` relationship scoped `development` in SPDX 3.0.1.
- Which format: CycloneDX 1.6 and SPDX 3.0.1 both meet the versions Germany's BSI asks for in TR-03183-2 (2.1); SPDX 2.3 is there for the many tools that read only 2.x.

The CRA does not require you to publish the SBOM: it belongs in your technical documentation, to be given to market surveillance authorities on request.

## Vulnerability scan

```sh
provetry scan [dir | sbom.json | image.tar] [--format text|markdown|json|sarif] [--out <file>]
              [--vex <file>]... [--vex-template <file>] [--fail-on <level>]
              [--include-dev] [--no-euvd] [--no-epss] [--offline] [--no-cache]
```

Sources, all free and public:

| Source | Used for |
|---|---|
| [OSV.dev](https://osv.dev) | Known vulnerabilities per package version, fixed versions, severity. OSV aggregates the GitHub advisories, PyPA, the Go and Rust advisory databases, RubySec and others. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities confirmed exploited in the wild, and those used in ransomware campaigns. |
| [ENISA EUVD](https://euvd.enisa.europa.eu) | The European database's list of exploited vulnerabilities. Best effort: the service publishes no stability guarantee, and a scan carries on without it, saying so. |
| [FIRST EPSS](https://www.first.org/epss/) | For CVEs not exploited yet: the probability, recomputed daily, that one is exploited in the next 30 days. A sorting aid only: without it nothing is missed, so a scan stays complete when it is down. |

How findings are ranked: exploited in the wild first, then those likely to be exploited soon (EPSS of 10% or more, a small minority of CVEs), then by severity (the highest CVSS 3.x base score the advisories carry, else the severity the advisory states), then direct dependencies before transitive ones. One vulnerability published by several databases (a GitHub advisory and a PyPI advisory for the same CVE) is shown once, with all its identifiers.

When a source cannot be reached, the report says the result is incomplete. If OSV itself cannot be reached, or a lock file cannot be read, the exit code is 2. With `--fail-on`, any incomplete result exits 2 too: a CI gate never passes on missing data.

Public data is cached in `~/.cache/provetry` (or `$PROVETRY_CACHE_DIR`), so repeated scans are quick: OSV answers per package for 6 hours, advisories for 30 days (keyed by their last modification), the KEV and EUVD lists and EPSS scores for 24 hours. File names are hashes; the only trace of your project is which package versions were looked up. `--offline` answers from that cache only.

## VEX: saying what does not affect you

A vulnerable library is not always a vulnerable product: the function at fault may never be called. [VEX](https://openvex.dev) is the standard way to record that. Pass your statements with `--vex` (OpenVEX or CycloneDX VEX, repeatable); findings you declared `not_affected` or `fixed` move to a separate section of the report, with your justification. A statement applies only to the components its products (or their subcomponents) name by package URL; a statement that names none is ignored, never applied to everything.

To start, `--vex-template vex.json` writes an OpenVEX file with one `under_investigation` statement per finding. Change each status as you assess it, and keep the file in your repository: it documents your vulnerability handling.

## Reachability: is the vulnerable code used?

Most vulnerabilities reported in dependencies cannot be reached from your product: the function at fault is never called. For Go, [govulncheck](https://go.dev/doc/security/vuln/) builds the call graph of your code and knows. `provetry reach` runs it in every Go module of the repository and writes one OpenVEX document:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
provetry reach . --product pkg:generic/gateway@2.4.0 --out reach.vex.json
provetry scan . --vex reach.vex.json
```

- Never called: `not_affected`, justification `vulnerable_code_not_in_execute_path` (or `vulnerable_code_not_present` when the vulnerable package is not even imported), with an impact statement naming the module checked.
- Called from any module: `affected`. Fix these first.
- It runs where your code and your Go toolchain are; nothing is sent anywhere.
- If govulncheck fails in one module, nothing that module depends on is declared not affected: it stays `under_investigation`.

What it cannot see, and the document says so: calls through reflection, cgo or plugins, and code built only for other platforms or build tags than the ones it ran with. The Go standard library is left out (govulncheck checks the Go that runs it, not necessarily the one that builds your product). Reachability is about your source code: when you describe a container image, other binaries in it are not covered.

### Other ecosystems: is the vulnerable package loaded at all?

For npm, PyPI, Cargo, Composer, RubyGems, NuGet and Java (Gradle, Maven), `provetry reach` reads the dependency graph in the lock files and the files of the whole repository (nothing is executed), then looks the vulnerabilities up (OSV.dev; `--offline` uses the cache only):

- **Never loaded**: nothing in the repository imports, names or runs the package, nor any package that leads to it. `not_affected`, justification `vulnerable_code_not_in_execute_path`, with the chain that brings it in (`left-pad > lodash`) as evidence. Typical cases: a dependency nobody uses any more, a heavy optional part of a library you do not touch, type packages.
- **Loaded**: imported by a file of the repository (file and line given), or depended on by something that is. `under_investigation`: at this level, nobody can say whether the vulnerable function itself is called.
- **Cannot tell**: nothing is said.

The dangerous mistake is to call a package unused when it is not, so every doubt counts as a use:

- A package named anywhere counts as used: in a configuration that loads plugins by name, a style sheet, a script of `package.json` (`node -r dotenv/config`), a Dockerfile, a Makefile, a Procfile, a shell script, a CI file, a Python string (`'django.db.backends.postgresql'`, `"mysql+pymysql://"`).
- Loaded whatever the code says: npm packages with an install script (seen in `package-lock.json` and pnpm lock files that record it; yarn.lock does not); Composer packages autoloaded on every request (`files`), Composer plugins, packages registered by Laravel's package discovery; every gem of the Gemfile with `Bundler.require`.
- No conclusion of absence when: import names are not sure (Python without a project virtual environment and outside a built-in list; packages with commands or plugin entry points; database drivers and servers started by name; Composer packages without a namespace or found at run time; every RubyGems, NuGet and Java package: Gradle lock files and `pom.xml` give no dependency graph); a lock file gives no complete graph (a `requirements.txt` not made by pip-compile) or cannot be analysed (`Pipfile.lock`); a file cannot be read (too many files, too large, a link outside the repository); code lives outside the repository (a linked folder, a Cargo path dependency).

**Rust, one level further.** RustSec advisories name the affected functions (`smallvec::SmallVec::insert_many`). When the project's own code is the only thing that loads the crate (no other loaded crate depends on it), uses none of its macros, and no file of the repository mentions any of those functions, the statement is `not_affected` with that evidence; when a file mentions one, the note gives the file and line to check first. No conclusion when Rust may call one of them without its name in the source: trait methods and operators (`<T as Drop>::drop`, `index`, `next`, `fmt`, `serialize`…), the crate's macros, attributes or derives used in the project, re-exports, code generated at build time (`OUT_DIR`, a `build.rs` that uses the crate). A name mentioned anywhere counts; functions of the crate that call the affected ones internally, and calls through another crate's generic code, are not seen.

**npm and PyPI, one level further (with a Provetry Pro or Consultant plan).** For these, advisories rarely name functions. Provetry reads the fix of each reviewed GitHub advisory and records the public functions of the package that lead to the code it changed; the service gives these records to its customers' CI (`PROVETRY_API_KEY` and `--provetry-url`; the GitHub action and the GitLab template pass them when the API key is set). When the project's own code is the only thing that loads the package and no file of the repository mentions any of them, the statement is `not_affected` with that evidence; when a file mentions one, the note gives the file and line. Nothing is concluded when the record has no function-level answer, or when methods lead to the fixed code (frameworks call them without the project writing their names). Records are checked (advisory, package, method), and only used for the same major and minor version as the one they were computed on. Without an account, this step reads nothing.

Where a file mentions one of those functions, a call analysis then looks for the call itself, through aliases and imports: [Jelly](https://github.com/cs-au-dk/jelly) (Aarhus University, BSD-3-Clause) for JavaScript and TypeScript, run with `npx` at a fixed version (or from `PROVETRY_JELLY`, the path of a local `jelly.js`), and a reading of the imports and calls of each file for Python. When it finds the call, the statement says so, with the file and line. It only adds evidence: these analyses miss some calls (a function passed as a callback, a re-export, a module copied with a spread), so a call they do not find changes nothing. `--no-calls` skips Jelly; with `--offline`, Jelly only runs from `PROVETRY_JELLY`. Jelly runs from a temporary folder (the repository's `.npmrc` and `node_modules` are not used to fetch or run it), without the pipeline's secrets in its environment, for at most 5 minutes and 4 GB of memory.

**Java (Maven), the same way, with the build's graph.** The records cover the public methods of Maven packages too. Java libraries also find each other at run time (service loaders, provider files, auto-configuration) without a dependency link, so a `not_affected` is only drawn for a **direct** dependency of the project that nothing else in the build depends on, and only from the full dependency graph the build writes: a CycloneDX SBOM next to the `pom.xml` or `gradle.lockfile` (`target/bom.json` from `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom`, or `build/reports/` from the `org.cyclonedx.bom` Gradle plugin), in which every component lists its dependencies. Without it, Java stays at the package level, as before. The SBOM is not used when it is older than the build file, misses a component the build file declares, links to something that is not a Maven component, or looks like a tree with its duplicates left out (nothing shared in a graph of ten components or more). Kotlin, Groovy, Scala, templates and configuration files (Spring XML, JSP, FreeMarker, properties, HOCON…) are searched for the names too. No conclusion either when the repository has code the sources do not show: annotation processors (Lombok, MapStruct, Dagger, Immutables, kapt, ksp), jars kept in the repository, `system`-scope or `files(…)` dependencies; nor for names Kotlin, Groovy or Scala call through their syntax (operators, indexing, destructuring).

What it cannot see: code that loads a package from a name built at run time, conventions of a framework that are not written in the repository. That is why, in the Provetry service, these results are suggestions with their evidence, which you accept or not; and why a CI gate does not rely on them: `--gate <file>` writes only govulncheck's statements, the ones `scan --vex` may use to pass a build (the GitHub action and the GitLab template do so).

## End of life of your components

```sh
provetry eol [dir | sbom.json] [--support-until 2031-12-31] [--json] [--offline] [--no-cache]
```

You must handle the vulnerabilities of your product for its whole support period (CRA, Article 13(8)), and exercise due diligence on the components you integrate (Article 13(5)). A component whose own support ends before yours will stop getting security fixes while you still owe them. `provetry eol` looks your components up on [endoflife.date](https://endoflife.date), finds the release cycle of each version, and flags those already unsupported (`!!`) or whose support ends before the date you give (`!`). Exit code 1 when one is flagged, 2 when some products could not be checked.

Only components endoflife.date knows by package URL are checked: frameworks, runtimes and databases mostly, not small libraries without a published support policy. Nothing is guessed for the others.

## Checking an evidence journal

```sh
provetry verify-journal provetry-journal.json --head <a hash you kept earlier> --tsa-ca <the authority's CA certificate>
```

The Provetry service keeps the manufacturer's decisions (assessments, reports submitted, exercises, advisories published) in a journal where each entry is chained to the one before by a SHA-256 hash. This command checks an exported journal: it recomputes every hash and says where the chain breaks, if it does (exit code 1). A consistent chain alone does not prove that nobody rewrote it from the start: keep the latest hash outside the service from time to time (each compliance dossier prints it) and pass it with `--head`; if it is no longer in a later export, the history was cut or rewritten. The export also carries RFC 3161 timestamps of the journal's head by an outside authority; the command checks that each one names an entry of the chain, that the signed token is for that entry's hash, and that its signature is valid. A valid signature does not say who signed: give the authority's CA certificate with `--tsa-ca` (for FreeTSA, `cacert.pem` from freetsa.org) to check that the authority did. Timestamps prove when the latest entries existed; entries first timestamped more than two days after the time they give are pointed out. They do not prove that the history before the oldest token is older: without `--head`, the command says that a journal rewritten from the start, then timestamped again, would also pass. The method: `hash = SHA-256(previous hash + "\n" + canonical JSON of {seq, at, workspace, actor, action, subject, details})`, keys sorted at every level, 64 zeros before the first entry.

## Article 14 reporting clock

```sh
provetry clock --since 2026-11-07T09:30:00Z [--fix <date>] [--incident [--notified <date>]] [--json]
```

```text
CRA Article 14 · actively exploited vulnerability · aware since 2026-11-07 09:30 UTC

Early warning  Art. 14(2)(a)  2026-11-08 09:30 UTC  (23 h 10 min left)
Notification   Art. 14(2)(b)  2026-11-10 09:30 UTC  (2 d 23 h left)
Final report   Art. 14(2)(c)  due 14 days after a corrective or mitigating measure is available
```

For a severe incident (`--incident`), the final report is due one month after the notification was submitted: give that date with `--notified`, otherwise Provetry shows the latest possible date. Reports go to the CSIRT designated as coordinator and to ENISA, through ENISA's single reporting platform. Micro and small enterprises cannot be fined for missing the 24-hour early warning (Article 64(10)), but the obligation itself applies to them.

## Using it in CI

### GitHub Actions

```yaml
on:
  push:
    tags: ['v*']
jobs:
  provetry:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v5        # only for Go projects: enables reachability
        with:
          go-version: stable
      - id: provetry
        # Pinned to a commit (version 0.9.0): this code receives your API key.
        uses: Enigmacker/provetry-core@38777e1406ad822e9c80d96674f8a7216e20778d
        with:
          fail-on: exploited
          # Optional: upload each release to Provetry (API key from Settings, product id from its page).
          api-key: ${{ secrets.PROVETRY_API_KEY }}
          product-id: 00000000-0000-0000-0000-000000000000
          # image: ghcr.io/acme/gateway:${{ github.ref_name }}   # describe a container image (or rootfs.tar.gz) instead
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.provetry.outputs.sarif }}
```

The version is the tag (`v2.4.0` becomes `2.4.0`). Uploads happen on tags only (`upload: always` to upload every run). A re-run of the same tag is fine; any other refusal fails the job. The SBOM, the reachability document and the SARIF report are in the step's outputs; the Markdown report goes to the job summary. With `image:`, reachability is skipped (it reads source code, not images); `platform: linux/arm64` picks the platform of a multi-platform image, and `image-tool: syft` uses Syft instead of Provetry's own reader. Upgrading from 0.9, where Syft read images: Provetry now reads them itself and says what it cannot read (RPM databases, Java archives, Go binaries); if your images rely on those, set `image-tool: syft`.

### GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/Enigmacker/provetry-core/main/ci/provetry.gitlab-ci.yml
```

Runs on every tag. Set `PROVETRY_API_KEY` and `PROVETRY_PRODUCT_ID` as CI/CD variables to upload, `PROVETRY_FAIL_ON` to fail the pipeline.

### Any CI

```sh
npx -y github:Enigmacker/provetry-core sbom . --name gateway --version "$VERSION" --out sbom.cdx.json
npx -y github:Enigmacker/provetry-core scan sbom.cdx.json --format sarif --out provetry.sarif --fail-on exploited
```

`--fail-on exploited` fails the build (exit 1) for vulnerabilities exploited in the wild; `critical`, `high`, `medium`, `low` and `any` are stricter. A finding exploited in the wild always reaches the threshold, whatever its score. If a source could not be checked and nothing reached the threshold, the exit code is 2, not 0. SARIF paths are relative to the directory you run the command from, so run it from the repository root.

## Privacy: which services see what

| Service | Receives |
|---|---|
| OSV.dev (Google) | The package URLs of your components (name and version). |
| CISA | A download of the public KEV catalogue. Nothing about you. |
| ENISA | A download of the public list of exploited vulnerabilities. Nothing about you. |
| FIRST | The CVE identifiers found in your components, to get their EPSS scores. |
| endoflife.date | A download of its list of package URLs, then the names of the products found among your components (`provetry eol` only). |
| npm registry | With `provetry reach`, when a vulnerable function is mentioned and `--no-calls` is not given: `npx` downloads Jelly (`@cs-au-dk/jelly@0.13.0`). Nothing about your project is sent. |
| Provetry (your account) | With `--provetry-url` and your API key: the GitHub advisory identifiers found in your npm and PyPI components, to get their vulnerable functions (`provetry reach` only). |

Your source code and lock files never leave your machine. `--no-euvd` skips ENISA, `--no-epss` skips FIRST; `--offline` sends nothing.

## Limitations

- Lock files only describe dependencies managed by a package manager. Code copied into your repository and system libraries are not seen: describe the container image or the root filesystem you ship (see above), or scan an SBOM from your build. In an image, RPM packages and statically linked binaries are not read yet.
- A known vulnerability in a dependency is a lead, not a verdict: whether it can be exploited in your product depends on how you use it. That is what VEX is for.
- CVSS 4.0 vectors are not computed; their severity comes from the advisory.
- `requirements.txt` gives exact versions only on `==` lines; others are skipped, and `-r` includes are not followed. Prefer a real lock file.
- Provetry does not write your coordinated vulnerability disclosure policy, ship your security updates or keep your technical documentation: the CRA asks for those too (Annex I, Part II, and Annex VII).

## Library use

```js
import { collect, toCycloneDx, scan, fetchJson, fileCache } from 'provetry';

const { components } = await collect('./my-project');
const sbom = toCycloneDx({ name: 'my-product', version: '2.4.0' }, components);
const result = await scan({ fetchJson, cache: fileCache() }, components);
```

`scan` takes the network as an argument (`fetchJson(url, { method, body }) → { status, json }`), so you can route it through your own client or test it without a network.

## Development

```sh
npm test
```

No dependency, so nothing to install. Tests run without network access against fixtures.

## License

[AGPL-3.0-only](LICENSE). Provetry is also a hosted service for teams that want the watch to run for them, with the reports and the technical documentation the CRA asks for: [provetry.com](https://provetry.com).
