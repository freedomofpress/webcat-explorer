// This module reads signing history from the webcat log auditor API.
// Sigstore history lists every Rekor entry whose certificate satisfies an enrollment's claims,
// with the extension's claim semantics. Sigsum history lists every leaf signed by one key.
const API = process.env.WEBCAT_AUDIT_API ?? "https://monitor-api.webcat.tech";
const LIMIT = 2000;

// get fetches one JSON answer. A burst gets 503 with Retry-After, so get waits once and retries.
async function get(path, params) {
  const url = `${API}${path}?${new URLSearchParams(params)}`;
  let r = await fetch(url, { signal: AbortSignal.timeout(30000) });
  if (r.status === 503) {
    await new Promise((f) => setTimeout(f, 1000 * Number(r.headers.get("retry-after") ?? 2)));
    r = await fetch(url, { signal: AbortSignal.timeout(30000) });
  }
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error ?? `${r.status} ${url}`);
  return body;
}

// pages follows the cursor until the answer is complete and returns every item plus the real total.
async function pages(path, params, field) {
  const items = [];
  let body, cursor;
  do {
    body = await get(path, { ...params, limit: LIMIT, ...(cursor && { cursor }) });
    items.push(...body[field]);
    cursor = body.cursor;
  } while (body.truncated && cursor);
  return { total: body.total, items };
}

export async function sigstoreHistory(claims) {
  const params = Object.fromEntries(Object.entries(claims).map(([oid, v]) => [`claims[${oid}]`, v]));
  const { total, items } = await pages("/v1/sigstore/history", params, "entries");
  return { total, entries: items };
}

export async function sigsumHistory(signer) {
  const { total, items } = await pages("/v1/sigsum/history", { signer }, "leaves");
  return { total, leaves: items };
}

export const auditorStatus = () => get("/v1/status", {});
