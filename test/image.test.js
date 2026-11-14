// Container images and firmware root filesystems: archives built here, in memory, then read back.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { readImage } from '../src/image/index.js';
import { osvOsPackage } from '../src/purl.js';
import { osvQuery, fixedVersions } from '../src/vuln/osv.js';
import { toCycloneDx } from '../src/sbom/write.js';

/** A minimal ustar writer: [{ path, data } | { path, link } | { path, dir: true }], with a pax header for long names. */
function tar(entries) {
  const blocks = [];
  const header = (name, size, type, link = '') => {
    const h = Buffer.alloc(512);
    h.write(name.slice(0, 100), 0, 'utf8');
    h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    h.write(size.toString(8).padStart(11, '0') + '\0', 124);
    h.write('00000000000\0', 136);
    h.fill(' ', 148, 156);
    h.write(type, 156);
    h.write(link, 157);
    h.write('ustar\0', 257); h.write('00', 263);
    let sum = 0; for (const b of h) sum += b;
    h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
    return h;
  };
  const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
  for (const e of entries) {
    if (e.path.length > 100) {
      const rec = ` path=${e.path}\n`;
      const len = String(rec.length + String(rec.length).length);
      const body = Buffer.from(`${Number(len) === rec.length + len.length ? len : rec.length + len.length + 1}${rec}`);
      blocks.push(header('PaxHeader', body.length, 'x'), pad(body));
    }
    if (e.dir) blocks.push(header(e.path, 0, '5'));
    else if (e.link) blocks.push(header(e.path, 0, '2', e.link));
    else { const d = Buffer.from(e.data); blocks.push(header(e.path, d.length, '0'), pad(d)); }
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}
const dir = mkdtempSync(join(tmpdir(), 'provetry-image-'));
const file = (name, buf) => { const p = join(dir, name); writeFileSync(p, buf); return p; };

const DEBIAN_OS = 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\n';
const DPKG = `Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 shared libraries

Package: zlib1g
Status: install ok installed
Architecture: amd64
Source: zlib (1:1.2.13.dfsg-1)
Version: 1:1.2.13.dfsg-1

Package: removed-thing
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0
`;

test('a firmware root filesystem (rootfs.tar.gz): dpkg, Python, a lock file', async () => {
  const p = file('rootfs.tar.gz', gzipSync(tar([
    { path: './etc', dir: true },
    { path: './usr/lib/os-release', data: DEBIAN_OS },
    { path: './etc/os-release', link: '../usr/lib/os-release' },
    { path: './var/lib/dpkg/status', data: DPKG },
    { path: './usr/lib/python3/dist-packages/six-1.16.0.egg-info', data: 'Metadata-Version: 1.2\nName: six\nVersion: 1.16.0\n' },
    { path: './usr/local/lib/python3.11/dist-packages/requests-2.31.0.dist-info/METADATA', data: 'Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n' },
    { path: './usr/local/lib/python3.11/site-packages/legacy-0.9-py3.11.egg-info', data: 'Metadata-Version: 1.1\nName: legacy\nVersion: 0.9\n' },
    { path: './root/.cache/pip/package-lock.json', data: JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/cached': { version: '9.9.9' } } }) },
    { path: './opt/app/test/fixtures/package-lock.json', data: JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/fixture': { version: '0.0.1' } } }) },
    { path: './usr/share/doc/thing/package-lock.json', data: JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/docdep': { version: '1.0.0' } } }) },
    { path: './opt/app/package-lock.json', data: JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { ms: '2.1.3' } }, 'node_modules/ms': { version: '2.1.3' } } }) },
    { path: './opt/app/node_modules/ms/package.json', data: JSON.stringify({ name: 'ms', version: '2.1.3' }) },
  ])));
  const r = await readImage(p);
  assert.equal(r.os.id, 'debian');
  const purls = r.components.map((c) => c.purl);
  assert.ok(purls.includes('pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl'), purls.join('\n'));
  assert.ok(purls.includes('pkg:deb/debian/zlib1g@1%3A1.2.13.dfsg-1?arch=amd64&distro=debian-12&upstream=zlib'), 'epoch encoded, source package kept');
  assert.ok(!purls.some((x) => x.includes('removed-thing')), 'a package removed (config files left) is not installed');
  assert.ok(purls.includes('pkg:pypi/requests@2.31.0'), 'installed with pip');
  assert.ok(purls.includes('pkg:pypi/legacy@0.9'), 'an egg-info that is a single file');
  assert.ok(!purls.some((x) => x.startsWith('pkg:pypi/six@')), 'installed by dpkg: listed once, as the Debian package');
  assert.ok(!purls.some((x) => /cached|fixture|docdep/.test(x)), 'lock files in caches, test fixtures and documentation describe nothing installed');
  assert.deepEqual(r.notices, []);
  const ms = r.components.find((c) => c.purl === 'pkg:npm/ms@2.1.3');
  assert.deepEqual(ms.sources.sort(), ['opt/app/node_modules/ms/package.json', 'opt/app/package-lock.json'], 'one component, both places');
  assert.deepEqual(r.errors, []);
  // The SBOM writer takes them as any other component.
  const bom = toCycloneDx({ name: 'gateway-firmware', version: '4.2.0' }, r.components);
  assert.ok(bom.components.some((c) => c.purl.startsWith('pkg:deb/debian/libssl3@')));
});

test('a container image saved with docker save: layers in order, whiteouts, an Alpine base', async () => {
  const base = tar([
    { path: 'etc/os-release', data: 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.19.1\n' },
    { path: 'lib/apk/db/installed', data: 'P:busybox\nV:1.36.1-r15\nA:x86_64\no:busybox\nL:GPL-2.0-only\n\nP:libcrypto3\nV:3.1.4-r5\nA:x86_64\no:openssl\n\n' },
    { path: 'usr/lib/node_modules/old-tool/package.json', data: JSON.stringify({ name: 'old-tool', version: '1.0.0' }) },
    { path: 'srv/a/node_modules/left/package.json', data: JSON.stringify({ name: 'left', version: '0.1.0' }) },
  ]);
  const app = gzipSync(tar([
    { path: 'usr/lib/node_modules/.wh.old-tool', data: '' },
    { path: 'srv/a/.wh..wh..opq', data: '' },
    { path: 'srv/a/node_modules/kept/package.json', data: JSON.stringify({ name: 'kept', version: '2.0.0' }) },
    { path: 'var/lib/rpm/rpmdb.sqlite', data: 'SQLite format 3\0' },
  ]));
  const archive = tar([
    { path: 'manifest.json', data: JSON.stringify([{ Config: 'config.json', RepoTags: ['acme/gateway:4.2.0'], Layers: ['l1/layer.tar', 'l2/layer.tar'] }]) },
    { path: 'l1/layer.tar', data: base },
    { path: 'l2/layer.tar', data: app },
  ]);
  const r = await readImage(file('image.tar', archive));
  assert.equal(r.name, 'acme/gateway');
  assert.equal(r.version, '4.2.0');
  const purls = r.components.map((c) => c.purl);
  assert.ok(purls.includes('pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64&distro=3.19.1&upstream=openssl'), purls.join('\n'));
  assert.ok(purls.includes('pkg:apk/alpine/busybox@1.36.1-r15?arch=x86_64&distro=3.19.1'));
  assert.ok(!purls.some((x) => x.includes('old-tool')), 'deleted by a whiteout in a later layer');
  assert.ok(!purls.some((x) => x.includes('/left@')), 'hidden by an opaque directory');
  assert.ok(purls.includes('pkg:npm/kept@2.0.0'));
  assert.ok(r.notices.some((n) => /RPM package databases are not read yet/.test(n.text) && n.incomplete), 'RPM databases are named, not silently skipped, and the result is incomplete');
});

test('an OCI image layout in one tar, through a multi-platform index', async () => {
  const layer = gzipSync(tar([
    { path: 'etc/os-release', data: 'ID=ubuntu\nVERSION_ID="22.04"\nID_LIKE=debian\n' },
    { path: 'var/lib/dpkg/status.d/bash', data: 'Package: bash\nVersion: 5.1-6ubuntu1.1\nArchitecture: amd64\n' },
  ]));
  const sha = (b) => createHash('sha256').update(b).digest('hex');
  const manifest = Buffer.from(JSON.stringify({ schemaVersion: 2, layers: [{ digest: `sha256:${sha(layer)}`, size: layer.length }] }));
  const index2 = Buffer.from(JSON.stringify({ schemaVersion: 2, manifests: [
    { digest: 'sha256:' + 'a'.repeat(64), platform: { os: 'linux', architecture: 'arm64' } },
    { digest: `sha256:${sha(manifest)}`, platform: { os: 'linux', architecture: 'amd64' } },
  ] }));
  const archive = tar([
    { path: 'oci-layout', data: '{"imageLayoutVersion":"1.0.0"}' },
    { path: 'index.json', data: JSON.stringify({ schemaVersion: 2, manifests: [{ digest: `sha256:${sha(index2)}`, annotations: { 'org.opencontainers.image.ref.name': 'gateway:4.2.0' } }] }) },
    { path: `blobs/sha256/${sha(index2)}`, data: index2 },
    { path: `blobs/sha256/${sha(manifest)}`, data: manifest },
    { path: `blobs/sha256/${sha(layer)}`, data: layer },
  ]);
  const r = await readImage(file('oci.tar', archive));
  assert.equal(r.name, 'gateway');
  assert.equal(r.version, '4.2.0');
  assert.deepEqual(r.notices, [], 'the arm64 image is not in the archive: one platform, nothing to choose');
  assert.deepEqual(r.components.map((c) => c.purl), ['pkg:deb/ubuntu/bash@5.1-6ubuntu1.1?arch=amd64&distro=ubuntu-22.04'], 'distroless-style status.d, Ubuntu namespace');
});

test('OSV: operating-system packages are looked up by ecosystem and release, with their source package', () => {
  const purl = 'pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl';
  assert.deepEqual(osvQuery(purl), { package: { name: 'openssl', ecosystem: 'Debian:12' }, version: '3.0.11-1~deb12u2' });
  assert.deepEqual(osvQuery('pkg:npm/ms@2.1.3'), { package: { purl: 'pkg:npm/ms@2.1.3' } });
  assert.equal(osvOsPackage('pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=3.19.1&upstream=openssl').ecosystem, 'Alpine:v3.19');
  assert.equal(osvOsPackage('pkg:deb/ubuntu/bash@5.2-2ubuntu1?distro=ubuntu-23.10').ecosystem, 'Ubuntu:23.10', 'not an LTS release');
  assert.equal(osvOsPackage('pkg:deb/debian/bash@5.2?arch=amd64'), null, 'no release: cannot be looked up');
  const rec = { affected: [
    { package: { ecosystem: 'Debian:12', name: 'openssl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.0.13-1~deb12u1' }] }] },
    { package: { ecosystem: 'Debian:11', name: 'openssl' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.1.1w-0+deb11u1' }] }] },
  ] };
  assert.ok(fixedVersions(rec, purl).includes('3.0.13-1~deb12u1'));
});

test('not an archive: a clear error', async () => {
  await assert.rejects(readImage(file('notes.txt', 'hello')), /neither a tar archive/);
});
