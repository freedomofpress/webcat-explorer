// This script builds site/data.json.
// It verifies the WEBCAT enrollment list the same way the extension's updater.ts does,
// then inspects every enrolled site and collects its transparency records.
import { readFile, writeFile } from "node:fs/promises";
import { importCommit, importValidators, verifyCommit } from "@freedomofpress/cometbft";
import { verifyWebcatProof } from "@freedomofpress/ics23/dist/webcat.js";
import { X509Certificate } from "@freedomofpress/sigstore-browser";
import { SigsumProof } from "@freedomofpress/sigsum/dist/proof.js";
import {
  b64url, enrollmentHash, extensionValue, extractHostname, extractRawHash, hex,
  sha256, canonicalize, validateManifest, validateSigstoreEnrollment,
  validateSigsumEnrollment, verifySigstoreManifest, verifySigsumManifest,
} from "./verify.mjs";
import { scanLogs } from "./scan.mjs";

// These values match the extension's config.ts defaults.
const ENDPOINT = "https://webcat.freedom.press/";
const CHAIN_ID = "webcat-test-02";
const BUNDLE_PATH = "/.well-known/webcat/bundle.json";
const BUNDLE_PREV_PATH = "/.well-known/webcat/bundle-prev.json";
const REKOR_V1 = "https://rekor.sigstore.dev";

const fetchJSON = async (url, init) => {
  const r = await fetch(url, { signal: AbortSignal.timeout(20000), ...init });
  if (!r.ok) throw new Error(`${r.status} ${url}`);
  return r.json();
};
const utf8 = (s) => new TextEncoder().encode(s);
const summarize = (x) => (x instanceof Error ? x.message : String(x));

// 1. Verify the list. This mirrors EnrollmentUpdater.update in the extension.
async function verifiedLeaves() {
  const validatorSet = JSON.parse(await readFile(new URL("./validator_set.json", import.meta.url)));
  const [block, list] = await Promise.all([fetchJSON(ENDPOINT + "block.json"), fetchJSON(ENDPOINT + "list.json")]);
  const { proto: vset, cryptoIndex } = await importValidators(validatorSet);
  const out = await verifyCommit(importCommit(block), vset, cryptoIndex, CHAIN_ID);
  if (!out.ok) throw new Error("block verification failed: " + JSON.stringify(out, (k, v) => (typeof v === "bigint" ? String(v) : v)));
  if (hex(out.appHash) !== list.proof.app_hash.toLowerCase()) throw new Error("app hash mismatch");
  const leaves = await verifyWebcatProof(list);
  if (leaves === false) throw new Error("proof did not verify against app hash");
  return {
    leaves,
    block: {
      chain_id: block.signed_header.header.chain_id,
      height: block.signed_header.header.height,
      time: block.signed_header.header.time,
      app_hash: list.proof.app_hash,
      canonical_root_hash: list.proof.canonical_root_hash,
      signed_power: `${out.signedPower}/${out.totalPower}`,
    },
  };
}

// 2. Fetch one bundle. This mirrors BundleFetcher.awaitAll in the extension.
async function fetchBundle(url) {
  let r;
  try {
    r = await fetch(url, { signal: AbortSignal.timeout(20000) });
  } catch (e) {
    return { error: "FETCH_ERROR", detail: summarize(e) };
  }
  if (!r.ok) return { error: "FETCH_ERROR", detail: String(r.status) };
  let b;
  try {
    b = await r.json();
  } catch {
    return { error: "MALFORMED" };
  }
  if (!b.enrollment) return { error: "ENROLLMENT_MISSING" };
  if (!b.manifest) return { error: "MANIFEST_MISSING" };
  if (!b.signatures) return { error: "SIGNATURES_MISSING" };
  return { value: b };
}

// 3. Collect transparency records.

// sigsumRecords parses each Sigsum proof and confirms the leaf exists in its log.
async function sigsumRecords(enrollment, bundle) {
  const logsByHash = {};
  for (const [pub, url] of Object.entries(enrollment.logs)) logsByHash[hex(await sha256(b64url(pub)))] = url;
  const canonical = canonicalize(bundle.manifest);
  const checksum = canonical === null ? null : hex(await sha256(await sha256(utf8(canonical))));
  const records = [];
  for (const [signer, proofText] of Object.entries(bundle.signatures)) {
    const r = { signer, signer_key_hash: hex(await sha256(b64url(signer))) };
    try {
      const p = await SigsumProof.fromAscii(proofText);
      r.log_key_hash = hex(p.logKeyHash.bytes);
      r.log_url = logsByHash[r.log_key_hash] ?? null;
      r.leaf_index = p.inclusion.LeafIndex;
      r.tree_size = p.treeHead.SignedTreeHead.TreeHead.Size;
      r.cosignatures = p.treeHead.Cosignatures.size;
      if (r.log_url) {
        r.leaf_url = `${r.log_url}/get-leaves/${r.leaf_index}/${r.leaf_index + 1}`;
        const text = await (await fetch(r.leaf_url, { signal: AbortSignal.timeout(20000) })).text();
        const line = text.split("\n").find((l) => l.startsWith("leaf="));
        const [c, sig, kh] = (line ?? "leaf=").slice(5).split(" ");
        r.in_log = sig === hex(p.leaf.Signature.bytes) && kh === hex(p.leaf.KeyHash.bytes) && c === checksum;
      }
    } catch (e) {
      r.error = summarize(e);
    }
    records.push(r);
  }
  return { sigsum: records };
}

// Fulcio certificate extensions. Every OIDC issuer uses the same OIDs.
// See https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
const FULCIO = {
  issuer_v1: "1.3.6.1.4.1.57264.1.1",
  issuer: "1.3.6.1.4.1.57264.1.8",
  build_signer: "1.3.6.1.4.1.57264.1.9",
  runner: "1.3.6.1.4.1.57264.1.11",
  repo: "1.3.6.1.4.1.57264.1.12",
  sha: "1.3.6.1.4.1.57264.1.13",
  ref: "1.3.6.1.4.1.57264.1.14",
  build_config: "1.3.6.1.4.1.57264.1.18",
  trigger: "1.3.6.1.4.1.57264.1.20",
  run: "1.3.6.1.4.1.57264.1.21",
};
const OTHERNAME_OID = "1.3.6.1.4.1.57264.1.7";

// ghWorkflow builds GitHub links for a workflow URI. Other issuers keep their URIs as issued.
const ghWorkflow = (uri) => {
  const m = /^(https:\/\/github\.com\/[^/]+\/[^/]+)\/(\.github\/workflows\/[^@]+)@(.+)$/.exec(uri ?? "");
  return m ? { repo: m[1], file: `${m[1]}/blob/${m[3]}/${m[2]}`, runs: `${m[1]}/actions/${m[2].replace(".github/", "")}` } : null;
};

// describeCert extracts the signer identity, the issuer, and every Fulcio extension from a certificate.
function describeCert(cert) {
  const san = cert.extSubjectAltName;
  const s = Object.fromEntries(Object.entries(FULCIO).map(([name, o]) => [name, extensionValue(cert, o)]));
  s.issuer ??= s.issuer_v1;
  delete s.issuer_v1;
  s.identity = san?.uri ?? san?.rfc822Name ?? san?.otherName(OTHERNAME_OID);
  s.identity_kind = san?.uri ? "uri" : san?.rfc822Name ? "email" : "othername";
  s.not_before = cert.notBefore.toISOString();
  if (s.issuer === "https://token.actions.githubusercontent.com") s.workflow = ghWorkflow(s.build_signer ?? s.identity);
  return s;
}

// rekorByHash lists every Rekor v1 entry for a manifest's SHA-256.
async function rekorByHash(manifest) {
  const canonical = canonicalize(manifest);
  if (canonical === null) return [];
  const h = hex(await sha256(utf8(canonical)));
  const uuids = await fetchJSON(`${REKOR_V1}/api/v1/index/retrieve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ hash: `sha256:${h}` }),
  });
  return uuids.map((uuid) => ({ uuid, url: `https://search.sigstore.dev/?uuid=${uuid}` }));
}

// sigstoreRecords describes each signing certificate and confirms each log entry exists in Rekor.
async function sigstoreRecords(enrollment, bundle, prev) {
  const logUrl = (keyId) => enrollment.trusted_root.tlogs?.find((t) => t.logId?.keyId === keyId)?.baseUrl ?? null;
  const signers = [];
  const entries = [];
  for (const sb of bundle.signatures) {
    const vm = sb.verificationMaterial ?? {};
    const raw = vm.certificate?.rawBytes ?? vm.x509CertificateChain?.certificates?.[0]?.rawBytes;
    if (raw) {
      try {
        signers.push(describeCert(X509Certificate.parse(new Uint8Array(Buffer.from(raw, "base64")))));
      } catch (e) {
        signers.push({ error: summarize(e) });
      }
    }
    for (const t of vm.tlogEntries ?? []) {
      const e = { log_url: logUrl(t.logId?.keyId), log_index: t.logIndex, integrated_time: t.integratedTime };
      if (e.log_url === REKOR_V1) {
        e.search_url = `https://search.sigstore.dev/?logIndex=${t.logIndex}`;
        try {
          const got = await fetchJSON(`${REKOR_V1}/api/v1/log/entries?logIndex=${t.logIndex}`);
          e.uuid = Object.keys(got)[0];
          e.found = true;
        } catch (err) {
          e.found = false;
          e.error = summarize(err);
        }
      } else {
        e.found = null; // Rekor v2 serves tiles, not entries by index. This build does not read tiles.
      }
      entries.push(e);
    }
  }
  // Rekor's search API cannot query by signing identity. The hash lookup for the
  // current and previous manifest is the closest public substitute.
  const by_hash = {};
  for (const [name, m] of [["current", bundle.manifest], ["previous", prev?.manifest]]) {
    if (!m) continue;
    try {
      by_hash[name] = await rekorByHash(m);
    } catch (e) {
      by_hash[name] = { error: summarize(e) };
    }
  }
  return { sigstore: { signers, entries, by_hash } };
}

// 4. Inspect one site. This mirrors OriginState.verifyEnrollment and verifyManifest in the extension.
async function inspect([key, hexHash]) {
  const host = extractHostname(key);
  const site = { host, canonical: key, enrollment_hash: hex(extractRawHash(hexHash)) };
  const [cur, prev] = await Promise.all([fetchBundle(`https://${host}${BUNDLE_PATH}`), fetchBundle(`https://${host}${BUNDLE_PREV_PATH}`)]);
  site.bundles = { current: cur.error ? `${cur.error} ${cur.detail ?? ""}`.trim() : "ok", previous: prev.error ? `${prev.error} ${prev.detail ?? ""}`.trim() : "ok" };
  if (cur.error) return { ...site, error: cur.error, detail: cur.detail };
  let bundle = cur.value, used = "current";
  if ((await enrollmentHash(bundle.enrollment)) !== site.enrollment_hash) {
    if (!prev.value || (await enrollmentHash(prev.value.enrollment)) !== site.enrollment_hash)
      return { ...site, error: "ENROLLMENT_MISMATCH" };
    bundle = prev.value;
    used = "previous";
  }
  site.bundle_used = used;
  const e = bundle.enrollment;
  site.enrollment = { ...e };
  delete site.enrollment.trusted_root; // The trusted root is large and the view does not use it.
  const m = bundle.manifest;
  // signed_at records when the manifest was signed. Sigsum uses the median witness
  // timestamp. Sigstore uses the certificate's notBefore, set below.
  if (e.type === "sigsum" && typeof m.timestamp === "string") {
    const ts = [...m.timestamp.matchAll(/^cosignature=\S+ (\d+)/gm)].map((x) => Number(x[1])).sort((a, b) => a - b);
    if (ts.length) site.signed_at = ts[Math.floor(ts.length / 2)];
  }
  site.manifest = { name: m.name ?? m.app, version: m.version, files: Object.keys(m.files ?? {}).length, wasm: (m.wasm ?? []).length, default_csp: m.default_csp, extra_csp: Object.keys(m.extra_csp ?? {}).length };
  let err = e.type === "sigsum" ? validateSigsumEnrollment(e) : e.type === "sigstore" ? validateSigstoreEnrollment(e) : "TYPE_INVALID";
  if (err) return { ...site, error: err };
  const vr = e.type === "sigsum" ? await verifySigsumManifest(e, m, bundle.signatures) : await verifySigstoreManifest(e, m, bundle.signatures);
  if (vr.error) Object.assign(site, vr);
  else site.valid_until = vr.validUntil;
  err = validateManifest(m);
  if (err && !site.error) site.error = err;
  // This build does not port validateCSP. The extension also validates each manifest's CSP.
  try {
    site.transparency = e.type === "sigsum" ? await sigsumRecords(e, bundle) : await sigstoreRecords(e, bundle, prev.value);
    const nb = site.transparency.sigstore?.signers?.[0]?.not_before;
    if (nb) site.signed_at = Math.floor(Date.parse(nb) / 1000);
  } catch (ex) {
    site.transparency = { error: summarize(ex) };
  }
  return site;
}

const { leaves, block } = await verifiedLeaves();
console.log(`list verified: ${leaves.length} leaves at height ${block.height}`);
// The build inspects all sites concurrently. Chunk this if the list grows past a few hundred sites.
const sites = await Promise.all(leaves.map((l) => inspect(l).catch((e) => ({ host: extractHostname(l[0]), canonical: l[0], error: "BUILD_ERROR", detail: summarize(e) }))));
sites.sort((a, b) => a.host.localeCompare(b.host));

// 5. Scan the Sigsum logs for every enrolled signer key.
const wanted = new Map();
for (const s of sites) for (const r of s.transparency?.sigsum ?? []) {
  for (const url of Object.values(s.enrollment.logs)) (wanted.get(url) ?? wanted.set(url, new Set()).get(url)).add(r.signer_key_hash);
}
const logs = {};
try {
  const scan = await scanLogs(wanted, new URL("./.cache/sigsum-scan.json", import.meta.url));
  for (const [url, l] of Object.entries(scan)) logs[url] = { size: l.size };
  for (const s of sites) for (const r of s.transparency?.sigsum ?? []) {
    r.history = Object.values(s.enrollment.logs).map((url) => ({ log_url: url, size: scan[url].size, leaves: scan[url].leaves[r.signer_key_hash] ?? [] }));
  }
} catch (e) {
  console.error("sigsum scan failed:", e);
  logs.error = summarize(e);
}

const data = { generated_at: new Date().toISOString(), block, logs, sites };
await writeFile(new URL("./site/data.json", import.meta.url), JSON.stringify(data, null, 1));
for (const s of sites) console.log(`${s.error ? "FAIL" : " ok "} ${s.host} ${s.enrollment?.type ?? ""} ${s.error ?? ""} ${s.detail ?? ""}`);
