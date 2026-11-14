// Container images and root filesystems: corrupt archives, layer semantics, releases, platforms, names.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import * as zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { readImage } from '../src/image/index.js';
import { readTar, indexTar } from '../src/image/tar.js';
import { distroOf, parseOsRelease, parseDpkgStatus, parseOpkgStatus } from '../src/image/packages.js';
import { osvOsPackage } from '../src/purl.js';
import { osvQuery, fixedVersions, affectedFunctions } from '../src/vuln/osv.js';

const dir = mkdtempSync(join(tmpdir(), 'provetry-image-edge-'));
const file = (name, buf) => { const p = join(dir, name); writeFileSync(p, buf); return p; };
const sha = (b) => createHash('sha256').update(b).digest('hex');
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);

/** One header block. `gnu`: GNU magic ("ustar  \0"); `size` may be a Buffer for raw size fields. */
function header({ name, size = 0, type = '0', link = '', prefix = '', gnu = false, sum = true }) {
  const h = Buffer.alloc(512);
  h.write(name, 0, 'utf8');
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  if (Buffer.isBuffer(size)) size.copy(h, 124); else h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write(type, 156);
  h.write(link, 157);
  if (gnu) h.write('ustar  \0', 257); else { h.write('ustar\0', 257); h.write('00', 263); }
  if (prefix) h.write(prefix, 345);
  h.fill(' ', 148, 156);
  let s = 0; for (const b of h) s += b;
  h.write((sum ? s : s + 1).toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}
const paxBody = (recs) => Buffer.from(Object.entries(recs).map(([k, v]) => {
  const rec = ` ${k}=${v}\n`;
  let n = rec.length + 1;
  while (String(n).length + rec.length !== n) n++;
  return `${n}${rec}`;
}).join(''));
const fileEntry = (name, data, extra = {}) => { const d = Buffer.from(data); return [header({ name, size: d.length, ...extra }), pad(d)]; };
const end = () => Buffer.alloc(1024);
const tarOf = (...parts) => Buffer.concat(parts.flat());
const entries = async (buf) => { const out = []; await readTar(Readable.from([buf]), (e) => { out.push(e); return 1e6; }, (e, d) => { e.data = d.toString(); }); return out; };
const tarFiles = (list) => tarOf(...list.map(([n, d]) => fileEntry(n, d)), end());

const DEB = 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n';

// ---------- the tar reader ----------

test('tar: a bad checksum, a size that is not a number, a negative base-256 size: errors, not loops', async () => {
  await assert.rejects(entries(tarOf(header({ name: 'a', sum: false }), end())), /bad checksum/);
  await assert.rejects(entries(tarOf(header({ name: 'a', size: Buffer.from('zzzzzzzzzzz\0') }), end())), /not a number/);
  const neg = Buffer.alloc(12, 0xff);
  await assert.rejects(entries(tarOf(header({ name: 'a', size: neg }), end())), /negative/);
  await assert.rejects(indexTar(file('neg.tar', tarOf(header({ name: 'a', size: neg }), end()))), /negative/);
  await assert.rejects(indexTar(file('nan.tar', tarOf(header({ name: 'a', size: Buffer.from('zzzzzzzzzzz\0') }), end()))), /not a number/);
});

test('tar: a truncated archive is an error, in the stream reader and the index', async () => {
  const full = tarFiles([['etc/os-release', DEB]]);
  const cut = full.subarray(0, 512 + 10);
  await assert.rejects(entries(cut), /truncated/);
  await assert.rejects(indexTar(file('cut.tar', cut)), /truncated/);
});

test('tar: base-256 sizes, header-only types carry no data, global pax ignored, GNU magic has no prefix', async () => {
  const b256 = Buffer.alloc(12); b256[0] = 0x80; b256[11] = 3;
  const gpax = paxBody({ path: 'global/should-not-apply' });
  const buf = tarOf(
    [header({ name: 'big', size: b256 }), pad(Buffer.from('abc'))],
    // A directory and a symlink whose size field is not zero: nothing follows them (as Go reads it).
    header({ name: 'd', type: '5', size: 512 }),
    header({ name: 'ln', type: '2', size: 512, link: 'big' }),
    [header({ name: 'g', type: 'g', size: gpax.length }), pad(gpax)],
    fileEntry('after', 'x'),
    // GNU headers use the prefix bytes for times: never part of the name.
    fileEntry('gnu-name', 'y', { gnu: true, prefix: 'garbage' }),
    fileEntry('name', 'z', { prefix: 'posix/prefix' }),
    end(),
  );
  const e = await entries(buf);
  assert.deepEqual(e.map((x) => [x.path, x.type]), [['big', 'file'], ['d', 'dir'], ['ln', 'symlink'], ['after', 'file'], ['gnu-name', 'file'], ['posix/prefix/name', 'file']]);
  assert.equal(e[0].data, 'abc');
  const idx = await indexTar(file('types.tar', buf));
  assert.deepEqual([...idx.keys()], ['big', 'ln', 'after', 'gnu-name', 'posix/prefix/name']);
  assert.deepEqual(idx.get('ln'), { link: 'big' });
});

test('tar: pax and GNU long names and link names, capped', async () => {
  const long = `${'a/'.repeat(80)}file`;
  const pax = paxBody({ path: long, linkpath: 'target/of/link' });
  const L = Buffer.from(`${'b/'.repeat(70)}gnu\0`);
  const K = Buffer.from(`${'c/'.repeat(70)}k\0`);
  const buf = tarOf(
    [header({ name: 'PaxHeader', type: 'x', size: pax.length }), pad(pax)], header({ name: 'short', type: '2' }),
    [header({ name: '././@LongLink', type: 'L', size: L.length }), pad(L)], [header({ name: '././@LongLink', type: 'K', size: K.length }), pad(K)], header({ name: 'x', type: '1' }),
    end(),
  );
  const e = await entries(buf);
  assert.deepEqual(e.map((x) => [x.path, x.linkname]), [[long, 'target/of/link'], [`${'b/'.repeat(69)}b/gnu`, `${'c/'.repeat(69)}c/k`]]);
  const idx = await indexTar(file('long.tar', buf));
  assert.deepEqual(idx.get(long), { link: `${'a/'.repeat(80).slice(0, -1)}/target/of/link`.replace(/^\//, '') }, 'pax linkpath in the index');
  assert.deepEqual(idx.get(`${'b/'.repeat(69)}b/gnu`), { link: `${'c/'.repeat(69)}c/k` }, 'GNU long link name in the index');
  const huge = Buffer.from((2 * 1024 * 1024).toString(8).padStart(11, '0') + '\0');
  await assert.rejects(entries(tarOf(header({ name: 'p', type: 'x', size: huge }), end())), /pax header too large/);
  await assert.rejects(entries(tarOf(header({ name: 'L', type: 'L', size: huge }), end())), /long name too large/);
});

// ---------- layers ----------

/** A docker save archive of the given layers (tar buffers). */
function dockerArchive(layers, extra = {}) {
  const names = layers.map((_, i) => `l${i}/layer.tar`);
  return tarFiles([['manifest.json', JSON.stringify([{ Config: 'c.json', RepoTags: ['acme/fw:1.0'], Layers: names, ...extra }])], ['c.json', '{}'], ...layers.map((l, i) => [names[i], l])]);
}
const pkgJson = (name, version) => JSON.stringify({ name, version });

test('layers: whiteouts hide lower layers only; a file replacing a directory hides what was under it', async () => {
  const lower = tarFiles([['etc/os-release', DEB], ['opt/a/node_modules/x/package.json', pkgJson('x', '1.0.0')], ['srv/node_modules/y/package.json', pkgJson('y', '1.0.0')]]);
  const upper = tarFiles([
    // An opaque directory and a whiteout, in the same layer as new files: the new files stay.
    ['opt/a/.wh..wh..opq', ''], ['opt/a/node_modules/z/package.json', pkgJson('z', '2.0.0')],
    ['srv/node_modules/.wh.w', ''], ['srv/node_modules/w/package.json', pkgJson('w', '3.0.0')],
    // srv/node_modules/y was a directory below: now a plain file.
    ['srv/node_modules/y', 'not a directory any more'],
  ]);
  const r = await readImage(file('layers.tar', dockerArchive([lower, upper])));
  const purls = r.components.map((c) => c.purl).sort();
  assert.deepEqual(purls, ['pkg:npm/w@3.0.0', 'pkg:npm/z@2.0.0']);
});

test('layers: a wanted file over its cap is an error, not a missing component', async () => {
  const big = 'P:x\nV:1\n' + 'x'.repeat(2 * 1024 * 1024 + 10);
  const r = await readImage(file('big.tar', tarFiles([['etc/os-release', DEB], ['usr/lib/node_modules/huge/package.json', big], ['opt/node_modules/ok/package.json', pkgJson('ok', '1.0.0')]])));
  assert.equal(r.errors.length, 1);
  assert.match(r.errors[0].error, /huge\/package\.json: too large to read/);
});

test('an archive compressed whole: a saved image (gzip) and a root filesystem (zstd)', async () => {
  const layer = tarFiles([['etc/os-release', DEB], ['var/lib/dpkg/status', 'Package: bash\nStatus: install ok installed\nVersion: 5.2.15-2+b2\n']]);
  const r = await readImage(file('image.tar.gz', gzipSync(dockerArchive([layer]))));
  assert.equal(r.name, 'acme/fw');
  assert.deepEqual(r.components.map((c) => c.purl), ['pkg:deb/debian/bash@5.2.15-2%2Bb2?distro=debian-12&upstream=bash%405.2.15-2'], 'binNMU: the source version');
  if (typeof zlib.zstdCompressSync === 'function') {
    const z = await readImage(file('rootfs.tar.zst', zlib.zstdCompressSync(layer)));
    assert.equal(z.components.length, 1);
  }
});

test('a root filesystem with a file named manifest.json at its root is still a root filesystem', async () => {
  const r = await readImage(file('rootfs-manifest.tar', tarFiles([['manifest.json', '{"app":"settings"}'], ['etc/os-release', DEB], ['var/lib/dpkg/status', 'Package: bash\nStatus: install ok installed\nVersion: 5.2\n']])));
  assert.equal(r.components.length, 1);
  assert.equal(r.name, '');
});

test('docker save of several images: the first is read, and the result says it is incomplete', async () => {
  const layer = tarFiles([['etc/os-release', DEB], ['var/lib/dpkg/status', 'Package: bash\nVersion: 5.2\n']]);
  const archive = tarFiles([
    ['manifest.json', JSON.stringify([{ Config: 'c.json', RepoTags: ['a:1'], Layers: ['l/layer.tar'] }, { Config: 'c.json', RepoTags: ['b:2'], Layers: ['l/layer.tar'] }])],
    ['c.json', '{}'], ['l/layer.tar', layer],
  ]);
  const r = await readImage(file('two.tar', archive));
  assert.ok(r.notices.some((n) => n.incomplete && /holds 2 images/.test(n.text)));
});

// ---------- OCI layouts ----------

function ociArchive({ platforms, annotations = {}, extraManifests = [], foreign = false, unsaved = [] }) {
  const blobs = [];
  const add = (buf) => { blobs.push([`blobs/sha256/${sha(buf)}`, buf]); return `sha256:${sha(buf)}`; };
  const manifests = platforms.map(([plat, osr]) => {
    const layer = gzipSync(tarFiles([['etc/os-release', osr], ['lib/apk/db/installed', `P:musl\nV:1.2.4-r2\nA:${plat.split('/')[1]}\n\n`]]));
    const layers = [{ mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: add(layer) }];
    if (foreign) layers.unshift({ mediaType: 'application/vnd.docker.image.rootfs.foreign.diff.tar.gzip', digest: `sha256:${'f'.repeat(64)}` });
    const m = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', layers }));
    const [os, architecture] = plat.split('/');
    return { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: add(m), platform: { os, architecture } };
  });
  const attest = Buffer.from(JSON.stringify({ schemaVersion: 2, layers: [{ mediaType: 'application/vnd.in-toto+json', digest: `sha256:${'e'.repeat(64)}` }] }));
  const missing = unsaved.map((plat, i) => ({ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: `sha256:${String(i).repeat(64)}`, platform: { os: plat.split('/')[0], architecture: plat.split('/')[1] } }));
  const index = Buffer.from(JSON.stringify({ schemaVersion: 2, manifests: [...missing, ...manifests, { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: add(attest), platform: { os: 'unknown', architecture: 'unknown' }, annotations: { 'vnd.docker.reference.type': 'attestation-manifest' } }] }));
  const top = [{ mediaType: 'application/vnd.oci.image.index.v1+json', digest: add(index), annotations }, ...extraManifests];
  return tarFiles([['oci-layout', '{"imageLayoutVersion":"1.0.0"}'], ['index.json', JSON.stringify({ schemaVersion: 2, manifests: top })], ...blobs]);
}
const ALPINE = 'ID=alpine\nVERSION_ID=3.19.1\n';

test('OCI: the platform asked for, attestations skipped, the full name from containerd', async () => {
  const p = file('multi.tar', ociArchive({ platforms: [['linux/amd64', ALPINE], ['linux/arm64', ALPINE]], annotations: { 'io.containerd.image.name': 'registry.example:5000/acme/gw:2.1', 'org.opencontainers.image.ref.name': '2.1' } }));
  const amd = await readImage(p);
  assert.match(amd.components[0].purl, /arch=amd64/);
  assert.equal(amd.name, 'registry.example:5000/acme/gw');
  assert.equal(amd.version, '2.1');
  assert.ok(amd.notices.some((n) => /2 platforms .*linux\/amd64 one is read, pass --platform/.test(n.text)), JSON.stringify(amd.notices));
  const arm = await readImage(p, { platform: 'linux/arm64' });
  assert.match(arm.components[0].purl, /arch=arm64/);
  await assert.rejects(readImage(p, { platform: 'linux/s390x' }), /no image for linux\/s390x .*linux\/amd64, linux\/arm64/);
});

test('OCI: only the platforms whose images were saved count (docker save keeps the whole index)', async () => {
  // An amd64 entry whose blobs were not saved, as docker save writes on an arm64 machine.
  const r = await readImage(file('arm-saved.tar', ociArchive({ platforms: [['linux/arm64', ALPINE]], unsaved: ['linux/amd64'] })));
  assert.match(r.components[0].purl, /arch=arm64/);
  assert.deepEqual(r.notices, []);
  await assert.rejects(readImage(file('arm-saved2.tar', ociArchive({ platforms: [['linux/arm64', ALPINE]], unsaved: ['linux/amd64'] })), { platform: 'linux/amd64' }), /no image for linux\/amd64 .*has: linux\/arm64/);
});

test('OCI: ref.name with only a tag is the version; an arm-only image is read as is', async () => {
  const r = await readImage(file('arm.tar', ociArchive({ platforms: [['linux/arm64', ALPINE]], annotations: { 'org.opencontainers.image.ref.name': '3.0' } })));
  assert.equal(r.name, '');
  assert.equal(r.version, '3.0');
  assert.match(r.components[0].purl, /arch=arm64/);
});

test('OCI: a foreign layer not in the archive is skipped, and the result is incomplete; several images are said', async () => {
  const r = await readImage(file('foreign.tar', ociArchive({ platforms: [['linux/amd64', ALPINE]], foreign: true, extraManifests: [{ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: `sha256:${'d'.repeat(64)}` }] })));
  assert.equal(r.components.length, 1);
  assert.ok(r.notices.some((n) => n.incomplete && /not in the archive/.test(n.text)));
  assert.ok(r.notices.some((n) => n.incomplete && /holds 2 images/.test(n.text)));
});

// ---------- releases and packages ----------

test('releases: derivatives as their parent, Wolfi and Chainguard, and those that cannot be looked up', () => {
  const d = (t) => distroOf(parseOsRelease(t));
  assert.deepEqual(d('ID=raspbian\nID_LIKE=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n'), { namespace: 'raspbian', family: 'debian', distro: 'debian-12', lookup: true, base: 'debian', derived: 'raspbian is looked up as Debian 12: packages of its own are not covered' });
  assert.equal(d('ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="21.3"\nVERSION_CODENAME=virginia\nUBUNTU_CODENAME=jammy\n').distro, 'ubuntu-22.04');
  assert.equal(d('ID=wolfi\nVERSION_ID=20230201\n').lookup, true);
  assert.equal(d('ID=debian\nPRETTY_NAME="Debian GNU/Linux trixie/sid"\nVERSION_CODENAME=trixie\n').distro, 'debian-13', 'testing: by code name');
  assert.equal(d('ID=debian\nPRETTY_NAME="Debian GNU/Linux sid"\n').lookup, false, 'unstable: no release');
  assert.equal(d('ID=alpine\nVERSION_ID=3.20_alpha20240329\nPRETTY_NAME="Alpine Linux edge"\n').lookup, false, 'edge: a snapshot');
  assert.equal(d('ID=alpine\nVERSION_ID=edge\n').lookup, false);
  assert.equal(d('ID=postmarketos\nID_LIKE=alpine\nVERSION_ID=v23.12\n').lookup, false);

  assert.deepEqual(osvQuery('pkg:deb/raspbian/libssl3@3.0.11-1~deb12u2+rpt1?distro=debian-12&upstream=openssl%403.0.11-1~deb12u2'), { package: { name: 'openssl', ecosystem: 'Debian:12' }, version: '3.0.11-1~deb12u2' });
  assert.equal(osvOsPackage('pkg:apk/wolfi/glibc@2.39-r1?arch=x86_64').ecosystem, 'Wolfi');
  assert.equal(osvOsPackage('pkg:apk/chainguard/glibc@2.39-r1').ecosystem, 'Chainguard');
  assert.equal(osvOsPackage('pkg:apk/alpine/musl@1.2.4?distro=edge'), null);
  assert.equal(osvOsPackage('pkg:apk/postmarketos/x@1?distro=postmarketos-v23.12'), null);
  assert.equal(osvOsPackage('pkg:deb/debian/x@1?distro=ubuntu-22.04'), null, 'a namespace and a release that disagree');
});

test('an image whose release cannot be looked up says so, and the result is incomplete', async () => {
  const r = await readImage(file('sid.tar', tarFiles([['etc/os-release', 'ID=debian\nPRETTY_NAME="Debian GNU/Linux sid"\n'], ['var/lib/dpkg/status', 'Package: bash\nVersion: 5.2\n']])));
  assert.ok(r.notices.some((n) => n.incomplete && /names no release/.test(n.text)), JSON.stringify(r.notices));
  const rpi = await readImage(file('rpi.tar', tarFiles([['etc/os-release', 'ID=raspbian\nID_LIKE=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n'], ['var/lib/dpkg/status', 'Package: bash\nVersion: 5.2\n']])));
  assert.equal(rpi.components[0].purl, 'pkg:deb/raspbian/bash@5.2?distro=debian-12');
  assert.ok(rpi.notices.some((n) => !n.incomplete && /looked up as Debian 12/.test(n.text)));
});

test('dpkg and opkg: only packages removed or never installed are left out; the source version is kept', () => {
  const st = (s) => `Package: p-${s.replace(/ /g, '-')}\nStatus: ${s}\nVersion: 1.0-1\n`;
  const text = ['install ok installed', 'install ok half-installed', 'install ok unpacked', 'hold ok installed', 'deinstall ok config-files', 'purge ok not-installed', 'install reinstreq half-configured'].map(st).join('\n');
  const names = parseDpkgStatus(text, 's', { namespace: 'debian', distro: 'debian-12' }).map((c) => c.name);
  assert.deepEqual(names, ['p-install-ok-installed', 'p-install-ok-half-installed', 'p-install-ok-unpacked', 'p-hold-ok-installed', 'p-install-reinstreq-half-configured']);
  assert.deepEqual(parseOpkgStatus(text, 's', null).length, 5);
  const [c] = parseDpkgStatus('Package: libz\nVersion: 1:1.3+b1\nSource: zlib (1:1.3)\n', 's', { namespace: 'debian', distro: 'debian-12' });
  assert.equal(c.purl, 'pkg:deb/debian/libz@1%3A1.3%2Bb1?distro=debian-12&upstream=zlib%401%3A1.3');
  assert.deepEqual(osvQuery(c.purl), { package: { name: 'zlib', ecosystem: 'Debian:12' }, version: '1:1.3' });
});

test('fixed versions: only those of the component\'s own release', () => {
  const purl = 'pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?distro=ubuntu-22.04&upstream=openssl';
  const rec = { affected: [
    { package: { ecosystem: 'Ubuntu:22.04:LTS', name: 'openssl' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '3.0.2-0ubuntu1.12' }] }], ecosystem_specific: { affects: { functions: ['f'] } } },
    { package: { ecosystem: 'Ubuntu:20.04:LTS', name: 'openssl' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '1.1.1f-1ubuntu2.20' }] }] },
    { package: { ecosystem: 'Ubuntu:Pro:22.04:LTS', name: 'openssl' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '9.9' }] }] },
  ] };
  assert.deepEqual(fixedVersions(rec, purl), ['3.0.2-0ubuntu1.12']);
  assert.deepEqual(affectedFunctions(rec, purl), ['f']);
  // Language packages still match their ecosystem whatever follows the colon.
  assert.deepEqual(fixedVersions({ affected: [{ package: { ecosystem: 'PyPI', name: 'Requests' }, ranges: [{ events: [{ fixed: '2.32.0' }] }] }] }, 'pkg:pypi/requests@2.31.0'), ['2.32.0']);
});
