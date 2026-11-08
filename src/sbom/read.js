// SPDX-License-Identifier: AGPL-3.0-only
// Reads an existing SBOM (CycloneDX or SPDX, JSON), for what Provetry cannot see in lock files:
// container images, firmware, vendor components. Produce it with your build tools (for example Syft),
// then scan it here.
import { parsePurl, fullName } from '../purl.js';

/** Returns { format, specVersion, name, version, components } from a parsed JSON SBOM. Throws on anything else. */
export function readSbom(json) {
  if (json?.bomFormat === 'CycloneDX') return readCycloneDx(json);
  if (typeof json?.spdxVersion === 'string') return readSpdx(json);
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
