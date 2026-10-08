// This module ports extension/src/webcat/{canonicalize,parsers,validators}.ts from
// freedomofpress/webcat. It keeps the upstream structure so a diff stays readable.
// Functions return the upstream WebcatErrorCode name as a string instead of a WebcatError object.
import {
  AllOf,
  EXTENSION_OID_OTHERNAME,
  PolicyError,
  SigstoreVerifier,
} from "@freedomofpress/sigstore-browser";
import { verifyMessageWithCompiledPolicy } from "@freedomofpress/sigsum";
import {
  evalQuorumBytecode,
  importAndHashAll,
  parseCompiledPolicy,
} from "@freedomofpress/sigsum/dist/compiledPolicy.js";
import {
  verifyCosignedTreeHead,
  verifySignedTreeHead,
} from "@freedomofpress/sigsum/dist/crypto.js";
import { parseCosignedTreeHead } from "@freedomofpress/sigsum/dist/proof.js";
import { Base64KeyHash, RawPublicKey } from "@freedomofpress/sigsum/dist/types.js";

export const b64url = (s) => new Uint8Array(Buffer.from(s, "base64url"));
export const hex = (u8) => Buffer.from(u8).toString("hex");
export const sha256 = async (u8) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", u8));

// canonicalize.ts: OLPC canonical JSON.
function canonicalizeString(s) {
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}
export function canonicalize(object) {
  if (typeof object === "string") return canonicalizeString(object);
  if (typeof object === "boolean" || Number.isInteger(object) || object === null)
    return JSON.stringify(object);
  if (Array.isArray(object)) {
    const parts = [];
    for (const el of object) {
      const enc = canonicalize(el);
      if (enc === null) return null;
      parts.push(enc);
    }
    return "[" + parts.join(",") + "]";
  }
  if (typeof object === "object") {
    const parts = [];
    for (const k of Object.keys(object).sort()) {
      const enc = canonicalize(object[k]);
      if (enc === null) return null;
      parts.push(canonicalizeString(k) + ":" + enc);
    }
    return "{" + parts.join(",") + "}";
  }
  return null;
}

// parsers.ts
export function extractHostname(key) {
  return key.replace(/^canonical\//, "").replace(/^\./, "").split(".").reverse().join(".");
}
export function extractRawHash(hexValue) {
  const bytes = Buffer.from(hexValue, "hex");
  if (bytes[0] !== 0x0a) throw new Error("Unexpected ICS23 prefix");
  return new Uint8Array(bytes.subarray(2, 2 + bytes[1]));
}

// originstate.ts: #enrollmentHash
export async function enrollmentHash(enrollment) {
  const c = canonicalize(enrollment);
  return c === null ? null : hex(await sha256(new TextEncoder().encode(c)));
}

// validators.ts
export async function witnessTimestampsFromCosignedTreeHead(compiledPolicy, treeHead) {
  const compiled = parseCompiledPolicy(compiledPolicy);
  const logs = await importAndHashAll(compiled.logsRaw);
  const witnesses = await importAndHashAll(compiled.witnessesRaw);
  const cth = parseCosignedTreeHead(treeHead.split("\n"));
  let logKeyHash = null;
  for (const log of logs) {
    if (await verifySignedTreeHead(cth.SignedTreeHead, log.pub, log.hash)) {
      logKeyHash = log.hash;
      break;
    }
  }
  if (!logKeyHash) throw new Error("no log key in policy verified the tree head");
  const present = new Uint8Array(witnesses.length);
  const timestamps = [];
  for (const [i, w] of witnesses.entries()) {
    const cosig = Base64KeyHash.lookup(cth.Cosignatures, w.b64);
    if (!cosig) continue;
    if (await verifyCosignedTreeHead(cth.SignedTreeHead.TreeHead, w.pub, logKeyHash, cosig)) {
      present[i] = 1;
      timestamps.push(cosig.Timestamp);
    }
  }
  if (!evalQuorumBytecode(compiled.quorum, witnesses.length, present))
    throw new Error("cosignature quorum not satisfied");
  return timestamps;
}

export function validateSigsumEnrollment(e) {
  if (typeof e.policy !== "string") return "POLICY_MALFORMED";
  if (e.policy.length === 0 || e.policy.length > 8192) return "POLICY_LENGTH";
  if (!Array.isArray(e.signers)) return "SIGNERS_MALFORMED";
  if (e.signers.length === 0) return "SIGNERS_EMPTY";
  if (e.signers.some((k) => typeof k !== "string")) return "SIGNERS_KEY_MALFORMED";
  if (typeof e.threshold !== "number" || !Number.isInteger(e.threshold) || e.threshold < 1)
    return "THRESHOLD_MALFORMED";
  if (e.threshold > e.signers.length) return "THRESHOLD_IMPOSSIBLE";
  if (typeof e.max_age !== "number" || !Number.isFinite(e.max_age)) return "MAX_AGE_MALFORMED";
  if (typeof e.logs !== "object" || e.logs === null || Object.keys(e.logs).length === 0)
    return "LOGS_MALFORMED";
  for (const [k, v] of Object.entries(e.logs))
    if (typeof k !== "string" || typeof v !== "string") return "LOGS_MALFORMED";
  return null;
}

export function validateSigstoreEnrollment(e) {
  if (!e.trusted_root) return "TRUSTED_ROOT_MISSING";
  if (typeof e.claims !== "object" || e.claims === null || Array.isArray(e.claims))
    return "CLAIMS_MISSING";
  if (Object.keys(e.claims).length < 1) return "CLAIMS_EMPTY";
  for (const [oid, v] of Object.entries(e.claims)) {
    if (typeof oid !== "string" || oid.length < 1) return "CLAIMS_MALFORMED";
    if (typeof v !== "string" || v.length < 1) return "CLAIMS_MALFORMED";
  }
  if (typeof e.max_age !== "number" || !Number.isFinite(e.max_age)) return "MAX_AGE_MALFORMED";
  return null;
}

const SHA256_BASE64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
export function validateManifest(m) {
  if (!m.files || Object.keys(m.files).length < 1) return "FILES_MISSING";
  for (const h of Object.values(m.files)) if (!SHA256_BASE64URL.test(h)) return "FILES_MALFORMED";
  if (!m.default_csp) return "DEFAULT_CSP_MISSING";
  if (!m.default_index) return "DEFAULT_INDEX_MISSING";
  if (!m.default_fallback) return "DEFAULT_FALLBACK_MISSING";
  if (!m.files["/" + m.default_index]) return "DEFAULT_INDEX_MISSING_FILE";
  if (!m.files[m.default_fallback]) return "DEFAULT_FALLBACK_MISSING_FILE";
  if (!m.wasm) return "WASM_MISSING";
  return null;
}

// verifySigsumManifest returns { validUntil } on success or { error, detail } on failure.
export async function verifySigsumManifest(enrollment, manifest, signatures) {
  if (typeof signatures !== "object" || signatures === null || Array.isArray(signatures))
    return { error: "SIGNATURES_MISSING" };
  const canonical = canonicalize(manifest);
  if (canonical === null) return { error: "VERIFY_FAILED" };
  const msg = new TextEncoder().encode(canonical);
  const remaining = new Set(enrollment.signers);
  let validCount = 0;
  for (const pubKey of Object.keys(signatures)) {
    if (!remaining.has(pubKey)) continue;
    try {
      await verifyMessageWithCompiledPolicy(
        msg,
        new RawPublicKey(b64url(pubKey)),
        b64url(enrollment.policy),
        signatures[pubKey],
      );
    } catch (e) {
      return { error: "VERIFY_FAILED", detail: String(e) };
    }
    remaining.delete(pubKey);
    validCount++;
  }
  if (validCount < enrollment.threshold)
    return { error: "THRESHOLD_UNSATISFIED", detail: `${validCount}/${enrollment.threshold}` };
  if (!manifest.timestamp) return { error: "TIMESTAMP_MISSING" };
  let timestamps;
  try {
    timestamps = await witnessTimestampsFromCosignedTreeHead(
      b64url(enrollment.policy),
      manifest.timestamp,
    );
  } catch (e) {
    return { error: "TIMESTAMP_VERIFY_FAILED", detail: String(e) };
  }
  const ts = timestamps.sort((a, b) => a - b)[Math.floor(timestamps.length / 2)];
  const now = Math.floor(Date.now() / 1000);
  if (now - ts > enrollment.max_age)
    return { error: "EXPIRED", detail: `signed ${ts}, max_age ${enrollment.max_age}` };
  return { validUntil: ts + enrollment.max_age };
}

// extensionValue decodes a Fulcio extension. Fulcio v1 wrote a raw OCTET STRING; v2 writes a DER UTF8String.
export function extensionValue(cert, oid) {
  const ext = cert.extension(oid);
  if (!ext) return undefined;
  const inner = ext.valueObj.subs?.[0];
  return new TextDecoder().decode(inner?.value ?? ext.value);
}

function claimMatches(expected, got) {
  return expected.startsWith("^") ? got.startsWith(expected.slice(1)) : got === expected;
}

class ClaimPolicy {
  constructor(oid, expected) {
    this.oid = oid;
    this.expected = expected;
  }
  verify(cert) {
    if (this.oid === "2.5.29.17") {
      const san = cert.extSubjectAltName;
      if (!san) throw new PolicyError("Certificate missing SubjectAlternativeName");
      const all = [san.rfc822Name, san.uri, san.otherName(EXTENSION_OID_OTHERNAME)].filter(Boolean);
      if (!all.some((s) => claimMatches(this.expected, s)))
        throw new PolicyError(`SAN mismatch for 2.5.29.17: expected '${this.expected}'`);
      return;
    }
    let got;
    try {
      got = extensionValue(cert, this.oid);
    } catch {
      throw new PolicyError(`Unable to decode extension ${this.oid}`);
    }
    if (got === undefined) throw new PolicyError(`Certificate missing extension ${this.oid}`);
    if (!claimMatches(this.expected, got))
      throw new PolicyError(`Extension ${this.oid} mismatch: got '${got}', expected '${this.expected}'`);
  }
}

class CertFreshnessPolicy {
  validUntil = 0;
  expired = undefined;
  constructor(maxAgeSeconds) {
    this.maxAgeSeconds = maxAgeSeconds;
  }
  verify(cert) {
    const now = Math.floor(Date.now() / 1000);
    const issued = Math.floor(cert.notBefore.getTime() / 1000);
    const validUntil = issued + this.maxAgeSeconds;
    if (now > validUntil) {
      this.expired = { error: "EXPIRED", detail: `issued ${issued}, max_age ${this.maxAgeSeconds}` };
      throw new PolicyError(`Signing certificate is too old: issued at ${issued}, max age ${this.maxAgeSeconds}s`);
    }
    if (!this.validUntil || this.validUntil > validUntil) this.validUntil = validUntil;
  }
}

// verifySigstoreManifest returns { validUntil } on success or { error, detail } on failure.
export async function verifySigstoreManifest(enrollment, manifest, signatures) {
  const verifier = new SigstoreVerifier();
  await verifier.loadSigstoreRoot(enrollment.trusted_root);
  const policies = Object.entries(enrollment.claims).map(([oid, v]) => new ClaimPolicy(oid, v));
  const freshness = new CertFreshnessPolicy(enrollment.max_age);
  policies.push(freshness);
  const policy = new AllOf(policies);
  if (!Array.isArray(signatures)) return { error: "SIGNATURES_MISSING" };
  const canonical = canonicalize(manifest);
  if (canonical === null) return { error: "VERIFY_FAILED" };
  const msg = new TextEncoder().encode(canonical);
  let lastError;
  for (const bundle of signatures) {
    try {
      if (await verifier.verifyArtifactPolicy(policy, bundle, msg)) return { validUntil: freshness.validUntil };
    } catch (e) {
      lastError = String(e);
    }
  }
  return freshness.expired ?? { error: "VERIFY_FAILED", detail: lastError };
}
