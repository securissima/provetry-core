import { test } from 'node:test';
import assert from 'node:assert/strict';
import { collect } from '../src/lockfiles/index.js';
import { parseGradleLock, readPom } from '../src/lockfiles/java.js';

test('gradle.lockfile: every resolved component; test-only configurations are development', () => {
  const c = parseGradleLock('a.b:c:1.0=compileClasspath\nx:y:2=testRuntimeClasspath\nempty=\n');
  assert.deepEqual(c.map((x) => [x.purl, x.scope]), [['pkg:maven/a.b/c@1.0', 'required'], ['pkg:maven/x/y@2', 'dev']]);
  assert.equal(parseGradleLock('a:b:1=classpath', { buildscript: true })[0].scope, 'dev', 'the build script does not ship');
  assert.throws(() => parseGradleLock('not a lock line'), /unexpected line/);
});

test('pom.xml: direct dependencies, properties and local management resolved; the rest said', () => {
  const { components, unresolved } = readPom(`<project><groupId>g</groupId><version>1</version>
    <properties><v>3</v></properties><dependencies>
    <dependency><groupId>a</groupId><artifactId>b</artifactId><version>\${v}</version></dependency>
    <dependency><groupId>c</groupId><artifactId>d</artifactId><version>[1,2)</version></dependency></dependencies></project>`);
  assert.deepEqual(components.map((x) => x.purl), ['pkg:maven/a/b@3']);
  assert.deepEqual(unresolved, ['c:d'], 'a range is not a version');
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
  assert.equal(r.notices.length, 1);
  assert.match(r.notices[0], /maven\/pom\.xml lists the direct dependencies only, and 1 without a version here .*spring-boot-starter-web.*CycloneDX Maven plugin/);
});

test('Java in the import analysis: evidence of use, never a conclusion of absence', async () => {
  const { usage } = await import('../src/usage/index.js');
  const u = await usage(new URL('./fixtures/java/', import.meta.url).pathname);
  assert.equal(u.components.get('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1').state, 'imported');
  assert.equal(u.components.get('pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0').state, 'unknown');
  assert.equal([...u.components.values()].some((x) => x.state === 'not_loaded'), false);
});
