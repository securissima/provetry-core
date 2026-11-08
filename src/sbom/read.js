// SPDX-License-Identifier: AGPL-3.0-only
// Reads an existing SBOM (CycloneDX or SPDX, JSON), for what Provetry cannot see in lock files:
// container images, firmware, vendor components. Produce it with your build tools (for example Syft),
// then scan it here.
import { parsePurl, fullName } from '../purl.js';

/** Returns { format, specVersion, name, version, components } from a parsed JSON SBOM. Throws on anything else. */
export function readSbom(json) {
  if (json?.bomFormat === 'CycloneDX') return readCycloneDx(json);
  if (typeof json?.spdxVersion === 'string') return readSpdx(json);
  if (isSpdx3(json)) return readSpdx3(json);
  throw new Error('not a CycloneDX or SPDX JSON document');
}

function fromPurl(purl, extra) {
  const p = parsePurl(purl);
  if (!p || !p.version) return null;
  return { type: p.type, name: fullName(p), version: p.version, purl, scope: 'required', sources: [], ...extra };
}

function readCycloneDx(bom) {
  const out = [];
  const walk = (list) => {
    for (const c of list ?? []) {
      if (c.purl) {
        const hashes = (c.hashes ?? []).filter((h) => h.alg && h.content).map((h) => ({ alg: h.alg, content: h.content }));
        const scope = c.scope === 'optional' ? 'optional' : c.scope === 'excluded' ? 'dev' : 'required';
        const comp = fromPurl(c.purl, { scope, hashes });
        if (comp) out.push(comp);
      }
      walk(c.components);
    }
  };
  walk(bom.components);
  const meta = bom.metadata?.component ?? {};
  // An SBOM that says it is incomplete stays incomplete for the scan (Provetry's own notes, or any tool's compositions).
  const props = bom.metadata?.properties ?? [];
  const missing = Number(props.find((p) => p?.name === 'provetry:unresolved')?.value ?? 0) || 0;
  const notes = props.filter((p) => p?.name === 'provetry:incomplete' && typeof p.value === 'string').map((p) => p.value);
  if (!notes.length && (bom.compositions ?? []).some((c) => /^incomplete/.test(c?.aggregate ?? ''))) notes.push('the SBOM says its inventory is incomplete');
  const notices = notes.map((text, i) => ({ text, missing: i === 0 ? missing : 0 }));
  return { format: 'CycloneDX', specVersion: bom.specVersion ?? '', name: meta.name ?? '', version: meta.version ?? '', components: out, notices };
}

const SPDX_TO_CDX = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA384: 'SHA-384', SHA512: 'SHA-512', MD5: 'MD5', 'SHA3-256': 'SHA3-256', 'SHA3-384': 'SHA3-384', 'SHA3-512': 'SHA3-512', 'BLAKE2b-256': 'BLAKE2b-256', 'BLAKE2b-384': 'BLAKE2b-384', 'BLAKE2b-512': 'BLAKE2b-512', BLAKE3: 'BLAKE3' };

function readSpdx(doc) {
  const out = [];
  const dev = new Set((doc.relationships ?? []).filter((r) => r.relationshipType === 'DEV_DEPENDENCY_OF').map((r) => r.spdxElementId));
  for (const p of doc.packages ?? []) {
    const ref = (p.externalRefs ?? []).find((r) => r.referenceType === 'purl');
    if (!ref) continue;
    const hashes = (p.checksums ?? []).filter((c) => SPDX_TO_CDX[c?.algorithm] && c.checksumValue).map((c) => ({ alg: SPDX_TO_CDX[c.algorithm], content: c.checksumValue }));
    const comp = fromPurl(ref.referenceLocator, { hashes, scope: dev.has(p.SPDXID) ? 'dev' : 'required' });
    if (comp) out.push(comp);
  }
  const c = /^Incomplete(?: \((\d+) unresolved direct dependencies\))?: (.*)$/s.exec(doc.creationInfo?.comment ?? '');
  const notices = c ? [{ text: c[2], missing: Number(c[1] ?? 0) }] : [];
  return { format: 'SPDX', specVersion: doc.spdxVersion, name: doc.name ?? '', version: '', components: out, notices };
}

// SPDX 3.x, JSON-LD: a graph of elements. Packages carry their package URL in software_packageUrl (or as an
// external identifier); development dependencies are the targets of a relationship scoped "development".
const isSpdx3 = (json) => [json?.['@context']].flat().some((c) => typeof c === 'string' && /^https:\/\/spdx\.org\/rdf\/3\./.test(c)) && Array.isArray(json['@graph']);
const SPDX3_TO_CDX = { sha1: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512', md5: 'MD5', sha3_256: 'SHA3-256', sha3_384: 'SHA3-384', sha3_512: 'SHA3-512', blake2b256: 'BLAKE2b-256', blake2b384: 'BLAKE2b-384', blake2b512: 'BLAKE2b-512', blake3: 'BLAKE3' };

function readSpdx3(doc) {
  const graph = doc['@graph'].filter((e) => e && typeof e === 'object');
  const short = (v) => String(v ?? '').replace(/^.*[/#]/, '');
  const kind = (e) => short(e?.type ?? e?.['@type']);
  const list = (v) => (Array.isArray(v) ? v : v != null ? [v] : []);
  const rels = graph.filter((e) => /Relationship$/.test(kind(e)));
  const dev = new Set();
  for (const rel of rels) {
    if (short(rel.relationshipType) === 'dependsOn' && ['development', 'build', 'test'].includes(short(rel.scope))) for (const t of list(rel.to)) dev.add(t);
  }
  const out = [];
  for (const e of graph) {
    if (!/^(software_)?Package$/.test(kind(e))) continue;
    const purl = e.software_packageUrl ?? list(e.externalIdentifier).find((x) => short(x?.externalIdentifierType) === 'packageUrl')?.identifier;
    if (typeof purl !== 'string') continue;
    const hashes = list(e.verifiedUsing).filter((h) => SPDX3_TO_CDX[short(h?.algorithm)] && typeof h.hashValue === 'string').map((h) => ({ alg: SPDX3_TO_CDX[short(h.algorithm)], content: h.hashValue }));
    const comp = fromPurl(purl, { hashes, scope: dev.has(e.spdxId) ? 'dev' : 'required' });
    if (comp) out.push(comp);
  }
  const docEl = graph.find((e) => kind(e) === 'SpdxDocument');
  const info = graph.find((e) => kind(e) === 'CreationInfo') ?? (typeof docEl?.creationInfo === 'object' ? docEl.creationInfo : null);
  const c = /^Incomplete(?: \((\d+) unresolved direct dependencies\))?: (.*)$/s.exec(typeof info?.comment === 'string' ? info.comment : '');
  const notices = c ? [{ text: c[2], missing: Number(c[1] ?? 0) }] : [];
  if (!notices.length && rels.some((rel) => short(rel.completeness) === 'incomplete')) notices.push({ text: 'the SBOM says its inventory is incomplete', missing: 0 });
  return { format: 'SPDX', specVersion: `SPDX-${typeof info?.specVersion === 'string' ? info.specVersion : '3'}`, name: typeof docEl?.name === 'string' ? docEl.name : '', version: '', components: out, notices };
}
