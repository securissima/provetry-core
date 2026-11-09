import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collect } from '../src/lockfiles/index.js';
import { parseGradleLock, parsePomText } from '../src/lockfiles/java.js';

test('gradle.lockfile: every resolved component; test-only configurations are development', () => {
  const c = parseGradleLock('a.b:c:1.0=compileClasspath,runtimeClasspath\nx:y:2=testRuntimeClasspath\nempty=\n');
  assert.deepEqual(c.map((x) => [x.purl, x.scope]), [['pkg:maven/a.b/c@1.0', 'required'], ['pkg:maven/x/y@2', 'dev']]);
  assert.equal(parseGradleLock('a:b:1=classpath', { buildscript: true })[0].scope, 'dev', 'the build script does not ship');
  assert.throws(() => parseGradleLock('not a lock line'), /unexpected line/);
});

test('gradle.lockfile: what ships is in a runtime classpath, not a test or debug-only one', () => {
  const c = parseGradleLock(['org.projectlombok:lombok:1.18.30=annotationProcessor,compileClasspath', 'leak:canary:2=debugRuntimeClasspath', 'ok:http:4=releaseRuntimeClasspath,debugRuntimeClasspath', 'kt:lint:1=ktlint'].join('\n'));
  assert.deepEqual(c.map((x) => x.scope), ['dev', 'dev', 'required', 'dev']);
});

test('pom.xml read alone: profiles active by default count, the others do not', () => {
  const p = parsePomText(`<project><groupId>g</groupId><version>1</version><properties><v>3</v></properties>
    <dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>\${v}</version></dependency></dependencies>
    <profiles><profile><properties><v>9</v></properties><dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency></dependencies></profile></profiles></project>`);
  assert.equal(p.properties.get('v'), '3', 'a property of an inactive profile does not win');
  assert.equal(p.dependencies.length, 1);
  assert.equal(p.inactiveDeps, 1);
});

test('a Gradle and a Maven project', async () => {
  const r = await collect(new URL('./fixtures/java/', import.meta.url).pathname);
  const by = new Map(r.components.map((c) => [c.purl, c]));
  assert.equal(by.get('pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0').direct, true);
  assert.equal(by.get('pkg:maven/com.fasterxml.jackson.core/jackson-core@2.13.0').direct, false);
  assert.equal(by.get('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1').direct, true, 'through the version catalog');
  assert.equal(by.get('pkg:maven/junit/junit@4.12').scope, 'dev');
  assert.equal(by.get('pkg:maven/org.yaml/snakeyaml@1.29').scope, 'required', 'version from dependencyManagement');
  assert.equal(by.get('pkg:maven/junit/junit@4.13.1').scope, 'dev');
  assert.equal([...by.keys()].some((p) => /gateway-core|not\/me|commented/.test(p)), false, 'own module, plugin dependencies and comments are left out');
  // The child module: parent's management and properties apply, CDATA read, exclusions not taken, active profile in.
  assert.ok(by.has('pkg:maven/org.apache.logging.log4j/log4j-api@2.14.1'));
  assert.ok(by.has('pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0'));
  assert.ok(by.has('pkg:maven/org.apache.commons/commons-text@1.9'));
  assert.equal([...by.keys()].some((p) => /cluded|old\/thing|not-appear/.test(p)), false, 'exclusions, inactive profiles and test POMs are left out');
  assert.equal(by.get('pkg:maven/com.squareup.okhttp3/okhttp@3.12.0').scope, 'required', 'Gradle before 6.8');
  const root = r.notices.find((n) => n.file === 'maven/pom.xml');
  assert.equal(root.missing, 1);
  assert.match(root.text, /direct dependencies only .*CycloneDX Maven plugin.*1 direct dependency has no version .*spring-boot-starter-web/);
  assert.match(r.notices.find((n) => n.file === 'maven/core/pom.xml').text, /1 dependency in profiles not active by default left out/);
});

test('Java in the import analysis: evidence of use, never a conclusion of absence', async () => {
  const { usage } = await import('../src/usage/index.js');
  const u = await usage(new URL('./fixtures/java/', import.meta.url).pathname);
  assert.equal(u.components.get('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1').state, 'imported');
  assert.equal(u.components.get('pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0').state, 'unknown');
  assert.equal([...u.components.values()].some((x) => x.state === 'not_loaded'), false);
});

test('incompleteness survives the SBOM: written, then read back by scan', async () => {
  const { toCycloneDx, toSpdx } = await import('../src/sbom/write.js');
  const { readSbom } = await import('../src/sbom/read.js');
  const cdx = toCycloneDx({ name: 'p' }, [], { incomplete: ['x lists the direct dependencies only'], unresolved: 2 });
  assert.deepEqual(readSbom(cdx).notices, [{ text: 'x lists the direct dependencies only', missing: 2 }]);
  const spdx = toSpdx({ name: 'p' }, [], { incomplete: ['y'], unresolved: 1 });
  assert.deepEqual(readSbom(spdx).notices, [{ text: 'y', missing: 1 }]);
  assert.deepEqual(readSbom(toCycloneDx({ name: 'p' }, [])).notices, []);
});

test('profiles: plugin dependencies are not the product; Android flavors', () => {
  const p = parsePomText(`<project><groupId>g</groupId><version>1</version><profiles><profile><activation><activeByDefault>true</activeByDefault></activation>
    <build><plugins><plugin><dependencies><dependency><groupId>org.ow2.asm</groupId><artifactId>asm</artifactId><version>9.0</version></dependency></dependencies></plugin></plugins></build>
    <dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></profile></profiles></project>`);
  assert.deepEqual(p.dependencies.map((d) => d.a), ['log4j-core']);
  const g = parseGradleLock('a:b:1=freeDebugRuntimeClasspath\nc:d:1=freeReleaseRuntimeClasspath');
  assert.deepEqual(g.map((x) => x.scope), ['dev', 'required']);
});

test('Java, function level: only with the build graph, for a direct dependency nothing else loads', async () => {
  const { usage } = await import('../src/usage/index.js');
  const { loadFunctionData, packageFunctions } = await import('../src/usage/functions.js');
  const { mkdtempSync, writeFileSync, mkdirSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const pom = '<project><groupId>acme</groupId><artifactId>app</artifactId><version>1</version><dependencies>'
    + '<dependency><groupId>com.github.junrar</groupId><artifactId>junrar</artifactId><version>7.5.0</version></dependency>'
    + '<dependency><groupId>org.unpack</groupId><artifactId>unpack-all</artifactId><version>1.0</version></dependency>'
    + '</dependencies></project>';
  const bom = (withUnpack) => JSON.stringify({
    bomFormat: 'CycloneDX', specVersion: '1.5', metadata: { component: { 'bom-ref': 'app', purl: 'pkg:maven/acme/app@1' } },
    components: [
      { 'bom-ref': 'j', purl: 'pkg:maven/com.github.junrar/junrar@7.5.0?type=jar' },
      { 'bom-ref': 'u', purl: 'pkg:maven/org.unpack/unpack-all@1.0?type=jar' },
    ],
    dependencies: [{ ref: 'app', dependsOn: ['j', 'u'] }, { ref: 'j', dependsOn: [] }, { ref: 'u', dependsOn: withUnpack ? ['j'] : [] }],
  });
  const make = (code, { withBom = true, unpackUsesJunrar = false, unpackImported = false } = {}) => {
    const dir = mkdtempSync(`${tmpdir()}/provetry-java-fn-`);
    writeFileSync(`${dir}/pom.xml`, pom);
    if (withBom) { mkdirSync(`${dir}/target`); writeFileSync(`${dir}/target/bom.json`, bom(unpackUsesJunrar)); }
    mkdirSync(`${dir}/src/main/java/acme`, { recursive: true });
    writeFileSync(`${dir}/src/main/java/acme/App.java`, `package acme;\nimport com.github.junrar.Archive;\n${unpackImported ? 'import org.unpack.Unpacker;\n' : ''}class App {\n${code}\n}\n`);
    return dir;
  };
  const record = { id: 'GHSA-89m4-43j5-vhhx', ecosystem: 'Maven', package: 'com.github.junrar:junrar', version: '7.5.0', entryPoints: ['extract'], methods: [], whole: false, method: 'provetry-vulnerable-functions/2 (fix diff + name graph)' };
  const ctx = { fetchJson: async () => ({ status: 200, json: [record] }) };
  const finding = { id: 'GHSA-89m4-43j5-vhhx', ids: ['GHSA-89m4-43j5-vhhx'], component: { type: 'maven', name: 'com.github.junrar:junrar', version: '7.5.0', purl: 'pkg:maven/com.github.junrar/junrar@7.5.0' } };
  const data = await loadFunctionData(ctx, [finding], { baseUrl: 'https://example.test/data' });
  assert.equal(data.size, 1, 'a Maven record is read');
  const key = `${finding.id}|${finding.component.purl}`;
  const run = async (code, opts) => { const dir = make(code, opts); const u = await usage(dir); return { r: await packageFunctions(dir, [finding], u.components, data), u: u.components.get(finding.component.purl) }; };

  let { r, u } = await run('void go() { new Archive(null); }');
  assert.equal(u.state, 'imported');
  assert.equal(u.direct, true);
  assert.equal(r.get(key).result, 'not_mentioned', 'the build graph says nothing else loads it, and the code never names extract');
  ({ r } = await run('void go() { Junrar.extract("a.rar", "out"); }'));
  assert.equal(r.get(key).result, 'mentioned');
  assert.equal(r.get(key).line, 4);
  ({ r } = await run('void go() { }', { withBom: false }));
  assert.equal(r.has(key), false, 'no build graph: no conclusion');
  ({ r } = await run('void go() { }', { unpackUsesJunrar: true, unpackImported: true }));
  assert.equal(r.has(key), false, 'another library the code loads depends on it: no conclusion');
});

test('Java build graph: refused when a component does not list its dependencies', async () => {
  const { javaBomGraph } = await import('../src/usage/graph.js');
  const ok = { bomFormat: 'CycloneDX', metadata: { component: { 'bom-ref': 'p' } }, components: [{ 'bom-ref': 'a', purl: 'pkg:maven/g/a@1' }], dependencies: [{ ref: 'p', dependsOn: ['a'] }, { ref: 'a', dependsOn: [] }] };
  assert.ok(javaBomGraph(JSON.stringify(ok)));
  assert.equal(javaBomGraph(JSON.stringify({ ...ok, dependencies: [{ ref: 'p', dependsOn: ['a'] }] })), null);
  assert.equal(javaBomGraph('not json'), null);
});
