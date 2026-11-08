// SPDX-License-Identifier: AGPL-3.0-only
// Writes the components as a CycloneDX 1.6, an SPDX 2.3 or an SPDX 3.0.1 document (JSON), the formats the CRA's
// "commonly used and machine-readable format" points to in practice.
import { randomUUID, createHash } from 'node:crypto';
import { TOOL } from '../version.js';

const CDX_HASH = new Set(['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'BLAKE2b-256', 'BLAKE2b-384', 'BLAKE2b-512', 'BLAKE3']);

/**
 * @param {{ name: string, version?: string, supplier?: string }} product the product the SBOM describes
 * @param {import('../lockfiles/index.js').Component[]} components
 * @param {{ now?: Date, serial?: string }} [opts]
 */
export function toCycloneDx(product, components, opts = {}) {
  const now = (opts.now ?? new Date()).toISOString();
  const rootRef = `product:${product.name}${product.version ? `@${product.version}` : ''}`;
  const comps = components.map((c) => {
    const out = { type: 'library', 'bom-ref': c.purl, name: c.name, version: c.version, purl: c.purl };
    if (c.scope === 'optional') out.scope = 'optional';
    if (c.scope === 'dev') out.scope = 'excluded';
    const hashes = (c.hashes ?? []).filter((h) => CDX_HASH.has(h.alg) && /^[0-9a-f]+$/i.test(h.content));
    if (hashes.length) out.hashes = hashes;
    const props = [];
    for (const s of c.sources ?? []) props.push({ name: 'provetry:source', value: s });
    if (c.direct) props.push({ name: 'provetry:direct', value: 'true' });
    if (props.length) out.properties = props;
    return out;
  });
  const direct = components.filter((c) => c.direct).map((c) => c.purl);
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: opts.serial ?? `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: now,
      lifecycles: [{ phase: 'build' }],
      tools: { components: [{ type: 'application', author: TOOL.vendor, name: TOOL.name, version: TOOL.version }] },
      ...(opts.incomplete?.length ? { properties: [...opts.incomplete.map((value) => ({ name: 'provetry:incomplete', value })), ...(opts.unresolved ? [{ name: 'provetry:unresolved', value: String(opts.unresolved) }] : [])] } : {}),
      component: {
        type: 'application',
        'bom-ref': rootRef,
        name: product.name,
        ...(product.version ? { version: product.version } : {}),
        ...(product.supplier ? { supplier: { name: product.supplier } } : {}),
      },
    },
    components: comps,
    // Said in the document itself: a reader must not take a partial inventory for a complete one.
    ...(opts.incomplete?.length ? { compositions: [{ aggregate: 'incomplete', assemblies: [rootRef] }] } : {}),
    // Top-level dependencies are what the CRA asks for at the very least (Annex I, Part II, point 1). When
    // no lock file said which ones they are, the graph is left out rather than guessed.
    ...(direct.length ? { dependencies: [{ ref: rootRef, dependsOn: direct }] } : {}),
  };
}

const SPDX_ALG = { 'SHA-1': 'SHA1', 'SHA-256': 'SHA256', 'SHA-384': 'SHA384', 'SHA-512': 'SHA512', MD5: 'MD5' };
const spdxId = (s) => `SPDXRef-${s.replace(/[^A-Za-z0-9.-]+/g, '-').slice(0, 200)}`;

export function toSpdx(product, components, opts = {}) {
  const now = (opts.now ?? new Date()).toISOString().replace(/\.\d+Z$/, 'Z');
  const rootId = 'SPDXRef-Product';
  const ids = new Set();
  const pkgs = components.map((c) => {
    let id = spdxId(`Package-${c.type}-${c.name}-${c.version}`);
    // Keep identifiers unique even when two names collapse to the same characters.
    if (ids.has(id)) id = `${id}-${createHash('sha256').update(c.purl).digest('hex').slice(0, 8)}`;
    ids.add(id);
    const checksums = (c.hashes ?? []).filter((h) => SPDX_ALG[h.alg] && /^[0-9a-f]+$/i.test(h.content)).map((h) => ({ algorithm: SPDX_ALG[h.alg], checksumValue: h.content.toLowerCase() }));
    return {
      SPDXID: id,
      name: c.name,
      versionInfo: c.version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      ...(checksums.length ? { checksums } : {}),
      externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: c.purl }],
      ...(c.scope === 'dev' ? { comment: 'Development dependency (not shipped).' } : {}),
    };
  });
  const name = `${product.name}${product.version ? `-${product.version}` : ''}`;
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name,
    documentNamespace: `https://provetry.com/spdx/${encodeURIComponent(name)}-${opts.serial ?? randomUUID()}`,
    creationInfo: { created: now, creators: [`Tool: ${TOOL.name}-${TOOL.version}`, ...(product.supplier ? [`Organization: ${product.supplier}`] : [])], ...(opts.incomplete?.length ? { comment: `Incomplete${opts.unresolved ? ` (${opts.unresolved} unresolved direct dependencies)` : ''}: ${opts.incomplete.join(' | ')}` } : {}) },
    packages: [
      {
        SPDXID: rootId,
        name: product.name,
        ...(product.version ? { versionInfo: product.version } : {}),
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        copyrightText: 'NOASSERTION',
        primaryPackagePurpose: 'APPLICATION',
        ...(product.supplier ? { supplier: `Organization: ${product.supplier}` } : {}),
      },
      ...pkgs,
    ],
    relationships: [
      { spdxElementId: 'SPDXRef-DOCUMENT', relationshipType: 'DESCRIBES', relatedSpdxElement: rootId },
      // Only what is known: the product depends directly on its top-level dependencies; development
      // dependencies are marked as such. Transitive components carry no relationship rather than a guessed one.
      ...pkgs.flatMap((p, i) =>
        components[i].scope === 'dev'
          ? [{ spdxElementId: p.SPDXID, relationshipType: 'DEV_DEPENDENCY_OF', relatedSpdxElement: rootId }]
          : components[i].direct
            ? [{ spdxElementId: rootId, relationshipType: 'DEPENDS_ON', relatedSpdxElement: p.SPDXID }]
            : [],
      ),
    ],
  };
}

// SPDX 3.0.1 (JSON-LD), the version Germany's BSI asks for in TR-03183-2 (2.1): the same content as the
// SPDX 2.3 document, in the 3.x model of elements and relationships, with the core and software profiles.
const SPDX3_ALG = {
  'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512', MD5: 'md5',
  'SHA3-256': 'sha3_256', 'SHA3-384': 'sha3_384', 'SHA3-512': 'sha3_512',
  'BLAKE2b-256': 'blake2b256', 'BLAKE2b-384': 'blake2b384', 'BLAKE2b-512': 'blake2b512', BLAKE3: 'blake3',
};

export function toSpdx3(product, components, opts = {}) {
  const now = (opts.now ?? new Date()).toISOString().replace(/\.\d+Z$/, 'Z');
  const name = `${product.name}${product.version ? `-${product.version}` : ''}`;
  const ns = `https://provetry.com/spdx/${encodeURIComponent(name)}-${opts.serial ?? randomUUID()}`;
  const ci = '_:creationinfo';
  const toolId = `${ns}#tool`;
  const orgId = `${ns}#supplier`;
  const creatorId = product.supplier ? orgId : `${ns}#creator`;
  const rootId = `${ns}#product`;
  const sbomId = `${ns}#sbom`;
  const ids = new Set();
  const pkgs = components.map((c) => {
    let id = `${ns}#${spdxId(`Package-${c.type}-${c.name}-${c.version}`).slice('SPDXRef-'.length)}`;
    if (ids.has(id)) id = `${id}-${createHash('sha256').update(c.purl).digest('hex').slice(0, 8)}`;
    ids.add(id);
    const hashes = (c.hashes ?? []).filter((h) => SPDX3_ALG[h.alg] && /^[0-9a-f]+$/i.test(h.content)).map((h) => ({ type: 'Hash', algorithm: SPDX3_ALG[h.alg], hashValue: h.content.toLowerCase() }));
    return {
      type: 'software_Package',
      spdxId: id,
      creationInfo: ci,
      name: c.name,
      software_packageVersion: c.version,
      software_packageUrl: c.purl,
      software_primaryPurpose: 'library',
      ...(hashes.length ? { verifiedUsing: hashes } : {}),
      ...(c.scope === 'dev' ? { comment: 'Development dependency (not shipped).' } : {}),
    };
  });
  // Only what is known, as in SPDX 2.3: the product depends on its top-level dependencies; transitive
  // components carry no relationship rather than a guessed one. Development dependencies, direct or not,
  // are the targets of a dependsOn scoped "development", so a reader can tell them apart. Completeness is
  // only asserted when it is known not to be: "incomplete" when something could not be resolved, and no
  // assertion otherwise (the list holds the top-level dependencies, not the whole tree).
  const rels = [];
  const direct = pkgs.filter((_, i) => components[i].direct && components[i].scope !== 'dev').map((p) => p.spdxId);
  const dev = pkgs.filter((_, i) => components[i].scope === 'dev').map((p) => p.spdxId);
  if (direct.length) rels.push({ type: 'Relationship', spdxId: `${ns}#depends-on`, creationInfo: ci, from: rootId, relationshipType: 'dependsOn', to: direct, ...(opts.incomplete?.length ? { completeness: 'incomplete' } : {}) });
  if (dev.length) rels.push({ type: 'LifecycleScopedRelationship', spdxId: `${ns}#dev-depends-on`, creationInfo: ci, from: rootId, relationshipType: 'dependsOn', scope: 'development', to: dev });
  const agents = [
    { type: 'Tool', spdxId: toolId, creationInfo: ci, name: `${TOOL.name}-${TOOL.version}` },
    // The author: the supplier when known; otherwise the software that wrote it, not a company.
    product.supplier
      ? { type: 'Organization', spdxId: creatorId, creationInfo: ci, name: product.supplier }
      : { type: 'SoftwareAgent', spdxId: creatorId, creationInfo: ci, name: TOOL.name },
  ];
  const root = {
    type: 'software_Package',
    spdxId: rootId,
    creationInfo: ci,
    name: product.name,
    ...(product.version ? { software_packageVersion: product.version } : {}),
    software_primaryPurpose: 'application',
    ...(product.supplier ? { suppliedBy: orgId } : {}),
  };
  const all = [rootId, ...pkgs.map((p) => p.spdxId), ...rels.map((r) => r.spdxId)];
  return {
    '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
    '@graph': [
      {
        type: 'CreationInfo',
        '@id': ci,
        specVersion: '3.0.1',
        created: now,
        createdBy: [creatorId],
        createdUsing: [toolId],
        ...(opts.incomplete?.length ? { comment: `Incomplete${opts.unresolved ? ` (${opts.unresolved} unresolved direct dependencies)` : ''}: ${opts.incomplete.join(' | ')}` } : {}),
      },
      ...agents,
      { type: 'SpdxDocument', spdxId: ns, creationInfo: ci, name, profileConformance: ['core', 'software'], rootElement: [sbomId], element: [sbomId, ...agents.map((a) => a.spdxId), ...all] },
      { type: 'software_Sbom', spdxId: sbomId, creationInfo: ci, software_sbomType: ['source'], rootElement: [rootId], element: all },
      root,
      ...pkgs,
      ...rels,
    ],
  };
}
