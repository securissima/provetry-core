// Copied from the Provetry service (shared/tsa.js): the same check on both sides.
// RFC 3161 timestamps: a time-stamping authority signs "this hash existed at this time". Used for the
// head of the evidence journal. The request is built by hand (a few bytes of DER). The answer is parsed
// and checked here: status, the hash inside the signed TSTInfo, the nonce, the CMS signature by the
// certificate in the token, and, when the authority's CA certificates are given, the chain to them.
// The whole answer is kept, so anyone can check it again with `openssl ts -verify`.
import { randomBytes, createHash, verify as cryptoVerify, X509Certificate } from 'node:crypto';

const len = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (tag, body) => Buffer.concat([Buffer.from([tag]), len(body.length), body]);
const SHA256_OID = Buffer.from('0609608648016503040201', 'hex'); // OBJECT IDENTIFIER 2.16.840.1.101.3.4.2.1

/** A DER INTEGER body, minimal and positive. */
function intBody(bytes) {
  let b = Buffer.from(bytes);
  while (b.length > 1 && b[0] === 0) b = b.subarray(1);
  return b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b;
}

/** TimeStampReq for a SHA-256 digest (hex), with a nonce, asking for the authority's certificate. */
export function timeStampRequest(digestHex, nonce = randomBytes(8)) {
  const digest = Buffer.from(digestHex, 'hex');
  if (digest.length !== 32) throw new Error('a SHA-256 digest is expected');
  const algo = tlv(0x30, Buffer.concat([SHA256_OID, Buffer.from([0x05, 0x00])]));
  const imprint = tlv(0x30, Buffer.concat([algo, tlv(0x04, digest)]));
  return tlv(0x30, Buffer.concat([Buffer.from([0x02, 0x01, 0x01]), imprint, tlv(0x02, intBody(nonce)), Buffer.from([0x01, 0x01, 0xff])]));
}

// ---- A small DER reader --------------------------------------------------------------------------

function node(buf, i) {
  if (i + 2 > buf.length) throw new Error('truncated DER');
  const tag = buf[i];
  let l = buf[i + 1];
  let start = i + 2;
  if (l & 0x80) {
    const k = l & 0x7f;
    if (k < 1 || k > 4 || start + k > buf.length) throw new Error('bad DER length');
    l = 0;
    for (let j = 0; j < k; j++) l = l * 256 + buf[start + j];
    start += k;
  }
  const end = start + l;
  if (end > buf.length) throw new Error('truncated DER');
  return { tag, start, end, raw: buf.subarray(i, end), body: buf.subarray(start, end) };
}
function children(buf, n) {
  const out = [];
  for (let i = n.start; i < n.end; ) { const c = node(buf, i); out.push(c); i = c.end; }
  return out;
}
const want = (n, tag, what) => { if (!n || n.tag !== tag) throw new Error(`unexpected DER: ${what}`); return n; };

function oid(body) {
  const parts = [Math.floor(body[0] / 40), body[0] % 40];
  let v = 0;
  for (let i = 1; i < body.length; i++) { v = v * 128 + (body[i] & 0x7f); if (!(body[i] & 0x80)) { parts.push(v); v = 0; } }
  return parts.join('.');
}
function genTime(body) {
  const m = /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.(\d+))?Z$/.exec(body.toString('latin1'));
  if (!m) throw new Error('bad genTime');
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], m[7] ? Math.floor(Number(`0.${m[7]}`) * 1000) : 0));
}

const HASHES = { '2.16.840.1.101.3.4.2.1': 'sha256', '2.16.840.1.101.3.4.2.2': 'sha384', '2.16.840.1.101.3.4.2.3': 'sha512' };
const SIGS = {
  '1.2.840.113549.1.1.1': null, // rsaEncryption: hash from the signer's digest algorithm
  '1.2.840.113549.1.1.11': 'sha256', '1.2.840.113549.1.1.12': 'sha384', '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256', '1.2.840.10045.4.3.3': 'sha384', '1.2.840.10045.4.3.4': 'sha512',
  '1.3.101.112': 'ed25519',
};
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const EKU_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';

/**
 * Does `cert` chain, through `pool`, to one of `anchors`? Intermediates must be CAs valid at `at`; each
 * certificate is visited once (a hostile token cannot make the search blow up).
 */
function chainsTo(cert, pool, anchors, at, seen = new Set()) {
  if (seen.size > 8) return false;
  seen.add(cert.fingerprint256);
  for (const a of anchors) {
    if (a.fingerprint256 === cert.fingerprint256) return true;
    if (cert.checkIssued(a) && cert.verify(a.publicKey)) return true;
  }
  for (const p of pool) {
    if (seen.has(p.fingerprint256) || !p.ca || at < new Date(p.validFrom) || at > new Date(p.validTo)) continue;
    if (cert.checkIssued(p) && cert.verify(p.publicKey) && chainsTo(p, pool, anchors, at, seen)) return true;
  }
  return false;
}

/** Reads PEM text with one or more certificates. */
export function readCertificates(pem) {
  return (String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []).map((c) => new X509Certificate(c));
}

/**
 * Checks a TimeStampResp for a SHA-256 digest (hex).
 * ok: granted, the digest is the one signed (messageImprint of the TSTInfo), the nonce matches when given,
 *     the CMS signature is valid with a certificate of the token that is allowed to timestamp and was valid
 *     at genTime.
 * trusted: that certificate chains to one of `trust` (X509Certificate list); null when none was given.
 * Without `trust`, the signer could be anyone: say so, and point to `openssl ts -verify` with the
 * authority's CA certificate.
 */
export function checkTimeStampResponse(resp, digestHex, { nonce, trust } = {}) {
  try {
    const buf = Buffer.from(resp);
    const top = want(node(buf, 0), 0x30, 'TimeStampResp');
    if (top.end !== buf.length) return { ok: false, reason: 'trailing bytes after the response' };
    const [statusInfo, token] = children(buf, top);
    const status = want(children(buf, want(statusInfo, 0x30, 'status'))[0], 0x02, 'status');
    const code = status.body.length <= 6 ? status.body.readUIntBE(0, status.body.length) : -1;
    if (code !== 0 && code !== 1) return { ok: false, reason: `refused (status ${code})` };
    if (!token) return { ok: false, reason: 'no token' };

    const [ctOid, ctBody] = children(buf, want(token, 0x30, 'ContentInfo'));
    if (oid(want(ctOid, 0x06, 'content type').body) !== OID_SIGNED_DATA) return { ok: false, reason: 'the token is not SignedData' };
    const sd = children(buf, want(children(buf, want(ctBody, 0xa0, 'content'))[0], 0x30, 'SignedData'));
    const encap = children(buf, want(sd[2], 0x30, 'encapContentInfo'));
    if (oid(want(encap[0], 0x06, 'eContentType').body) !== OID_TSTINFO) return { ok: false, reason: 'the token does not hold a TSTInfo' };
    const eContent = want(children(buf, want(encap[1], 0xa0, 'eContent'))[0], 0x04, 'eContent');
    const certsNode = sd.find((n) => n.tag === 0xa0);
    const signerInfos = want(sd[sd.length - 1], 0x31, 'signerInfos');

    // TSTInfo: version, policy, messageImprint, serialNumber, genTime, [accuracy], [ordering], [nonce]…
    const t = eContent.body;
    const tst = children(t, want(node(t, 0), 0x30, 'TSTInfo'));
    const [imAlg, imHash] = children(t, want(tst[2], 0x30, 'messageImprint'));
    if (oid(children(t, imAlg)[0].body) !== '2.16.840.1.101.3.4.2.1') return { ok: false, reason: 'the token is not over a SHA-256 hash' };
    if (!want(imHash, 0x04, 'hashedMessage').body.equals(Buffer.from(digestHex, 'hex'))) return { ok: false, reason: 'the token is for another hash' };
    const at = genTime(want(tst[4], 0x18, 'genTime').body);
    const tstNonce = tst.slice(5).find((n) => n.tag === 0x02);
    if (nonce && (!tstNonce || !tstNonce.body.equals(intBody(nonce)))) return { ok: false, reason: 'the nonce does not match the request' };

    // The signer: signed attributes hold the content type and the hash of the TSTInfo; the signature is over them.
    const si = children(buf, want(children(buf, signerInfos)[0], 0x30, 'SignerInfo'));
    const digestAlg = HASHES[oid(children(buf, si[2])[0].body)];
    if (!digestAlg) return { ok: false, reason: 'unknown digest algorithm' };
    const signed = want(si[3], 0xa0, 'signedAttrs');
    let ctOk = false; let md = null;
    for (const a of children(buf, signed)) {
      const [aOid, vals] = children(buf, a);
      const id = oid(aOid.body); const v = children(buf, vals)[0];
      if (id === OID_CONTENT_TYPE) ctOk = oid(v.body) === OID_TSTINFO;
      if (id === OID_MESSAGE_DIGEST) md = v.body;
    }
    if (!ctOk || !md) return { ok: false, reason: 'signed attributes incomplete' };
    if (!md.equals(createHash(digestAlg).update(t).digest())) return { ok: false, reason: 'the TSTInfo does not match its signed hash' };
    const sigAlgOid = oid(children(buf, want(si[4], 0x30, 'signatureAlgorithm'))[0].body);
    if (!(sigAlgOid in SIGS)) return { ok: false, reason: `unsupported signature algorithm ${sigAlgOid}` };
    const sigHash = SIGS[sigAlgOid] === 'ed25519' ? null : (SIGS[sigAlgOid] ?? digestAlg);
    const signature = want(si[5], 0x04, 'signature').body;
    const toVerify = Buffer.concat([Buffer.from([0x31]), signed.raw.subarray(1)]); // [0] IMPLICIT → SET

    const certNodes = certsNode ? children(buf, certsNode).filter((c) => c.tag === 0x30) : [];
    if (certNodes.length > 10) return { ok: false, reason: 'too many certificates in the token' };
    const certs = certNodes.map((c) => new X509Certificate(c.raw));
    const signer = certs.find((c) => { try { return cryptoVerify(sigHash, toVerify, c.publicKey, signature); } catch { return false; } });
    if (!signer) return { ok: false, reason: 'the signature does not verify with a certificate of the token' };
    if (!(signer.keyUsage ?? []).includes(EKU_TIMESTAMPING)) return { ok: false, reason: 'the signing certificate is not for timestamping' };
    if (at < new Date(signer.validFrom) || at > new Date(signer.validTo)) return { ok: false, reason: 'the signing certificate was not valid at that time' };

    const trusted = trust?.length ? chainsTo(signer, certs, trust, at) : null;
    if (trusted === false) return { ok: false, reason: 'the signing certificate does not chain to the given authority' };
    return { ok: true, genTime: at.toISOString(), signer: signer.subject.replace(/\n/g, ', '), signerFingerprint: signer.fingerprint256, trusted };
  } catch (e) {
    return { ok: false, reason: `unreadable token (${e.message})` };
  }
}
