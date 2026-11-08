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
