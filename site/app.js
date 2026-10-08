// This app renders site/data.json. The build writes that file daily.
// The app uses no inline script or style, so it can itself be enrolled in WEBCAT.

// Rendering helpers. Every value goes through esc() before it reaches innerHTML.
const PAGE = 10;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const a = (href, text) => (href ? `<a href="${esc(href)}" target="_blank" rel="noopener">${esc(text ?? href)}</a>` : "");
const ts = (s) => (s ? new Date(Number(s) * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "");
const presence = (v) => (v === true ? '<b class="ok">✓ found</b>' : v === false ? '<b class="fail">✗ not found</b>' : '<b class="warn">? not checked</b>');
const code = (s) => (s ? `<code>${esc(s)}</code>` : "");
const dl = (pairs) => `<dl>${pairs.filter(([, v]) => v !== undefined && v !== "" && v !== null).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
const $ = (id) => document.getElementById(id);

// Human names for Fulcio OIDs and OIDC issuers. The raw value stays in a tooltip.
const OID = { "2.5.29.17": "identity (SAN)", "1.3.6.1.4.1.57264.1.1": "issuer (v1)", "1.3.6.1.4.1.57264.1.8": "issuer", "1.3.6.1.4.1.57264.1.9": "build signer", "1.3.6.1.4.1.57264.1.10": "build signer digest", "1.3.6.1.4.1.57264.1.11": "runner", "1.3.6.1.4.1.57264.1.12": "source repo", "1.3.6.1.4.1.57264.1.13": "source commit", "1.3.6.1.4.1.57264.1.14": "source ref", "1.3.6.1.4.1.57264.1.15": "repo id", "1.3.6.1.4.1.57264.1.16": "repo owner", "1.3.6.1.4.1.57264.1.17": "owner id", "1.3.6.1.4.1.57264.1.18": "build config", "1.3.6.1.4.1.57264.1.19": "build config digest", "1.3.6.1.4.1.57264.1.20": "trigger", "1.3.6.1.4.1.57264.1.21": "run", "1.3.6.1.4.1.57264.1.22": "visibility" };
const oid = (o) => OID[o] ? `<span title="${esc(o)}">${esc(OID[o])}</span>` : code(o);
const short = (h, n = 10) => h ? `<code title="${esc(h)}">${esc(h.slice(0, n))}…${esc(h.slice(-4))}</code>` : "";
const day = (s) => s ? new Date(Number(s) * 1000).toISOString().slice(0, 10) : "";
const sub = (title, body) => `<details class="sub"><summary>${title}</summary><div>${body}</div></details>`;
const repoName = (u) => (u ?? "").replace(/^https?:\/\/(github\.com|gitlab\.com)\//, "").replace(/^https?:\/\//, "");
const ISSUER = { "https://token.actions.githubusercontent.com": "GitHub Actions", "https://gitlab.com": "GitLab CI", "https://ops.gitlab.net": "GitLab CI", "https://accounts.google.com": "Google account", "https://github.com/login/oauth": "GitHub account", "https://login.microsoftonline.com": "Microsoft account", "https://oauth2.sigstore.dev/auth": "Sigstore OAuth" };
const issuerName = (i) => i ? `<span title="${esc(i)}">${esc(ISSUER[i] ?? new URL(i).hostname)}</span>` : "";
const shortRef = (r) => esc(r?.replace(/^refs\/(tags|heads)\//, ""));
const tbd = (what, why) => `<span class="tbd" title="${esc(why)}">${esc(what)}: TBD</span>`;

// Short status words for the badge. The raw error code stays in a tooltip.
const STATUS = { ENROLLMENT_MISMATCH: "Hash mismatch", FETCH_ERROR: "No bundle", MALFORMED: "Malformed bundle", EXPIRED: "Expired", VERIFY_FAILED: "Bad signature", THRESHOLD_UNSATISFIED: "Too few signatures", TIMESTAMP_MISSING: "No log proof", TIMESTAMP_VERIFY_FAILED: "Bad log proof", TYPE_INVALID: "Unknown type", BUILD_ERROR: "Build error" };
const statusLabel = (s) => s.error ? (STATUS[s.error] ?? s.error.toLowerCase().replace(/_/g, " ")) : "Verified";
const statusBadge = (s) => `<b class="badge ${s.error ? "fail" : "ok"}" title="${esc(s.error ?? "")}">${s.error ? "✗" : "✓"} ${esc(statusLabel(s))}</b>`;

// checks() maps the site's error code onto the extension's verification steps.
// The extension stops at the first failure, so later steps show as skipped.
// A step marked independent keeps its own result, because the build gathered that evidence separately.
const BUNDLE_ERRS = ["FETCH_ERROR", "MALFORMED", "ENROLLMENT_MISSING", "MANIFEST_MISSING", "SIGNATURES_MISSING"];
const ENROLL_ERRS = /^(POLICY_|SIGNERS_|THRESHOLD_MALFORMED|THRESHOLD_IMPOSSIBLE|MAX_AGE_|LOGS_|TRUSTED_ROOT_|CLAIMS_|TYPE_INVALID)/;
const MANIFEST_ERRS = /^(FILES_|DEFAULT_|WASM_)/;
function checks(s) {
  const t = s.transparency ?? {}, e = s.error;
  const logOk = t.sigsum ? t.sigsum.every((r) => r.in_log !== false) : t.sigstore ? t.sigstore.entries.every((r) => r.found !== false) : true;
  const steps = [
    ["Listed on chain", true, ""],
    ["Bundle fetched", !BUNDLE_ERRS.includes(e), s.bundle_used ? `${s.bundle_used} bundle` : s.detail ?? ""],
    ["Enrollment hash", e !== "ENROLLMENT_MISMATCH", ""],
    ["Enrollment format", !ENROLL_ERRS.test(e ?? ""), ""],
    ["Manifest signature", !["VERIFY_FAILED", "THRESHOLD_UNSATISFIED", "SIGNATURES_MISSING"].includes(e), e === "VERIFY_FAILED" ? "did not verify" : ""],
    ["Log proof", !["TIMESTAMP_MISSING", "TIMESTAMP_VERIFY_FAILED"].includes(e) && logOk, logOk ? "" : "entry not found in log", !logOk],
    ["Fresh", e !== "EXPIRED", e === "EXPIRED" ? `max_age ${Math.round((s.enrollment?.max_age ?? 0) / 86400)} days` : ""],
    ["Manifest format", !MANIFEST_ERRS.test(e ?? ""), ""],
  ];
  let failed = false;
  return `<ol class="checks">${steps.map(([label, ok, note, independent]) => {
    const state = failed && !independent ? "skip" : ok ? "ok" : "fail";
    if (!ok) failed = true;
    return `<li class="${state}"><span>${state === "ok" ? "✓" : state === "fail" ? "✗" : "·"}</span>${esc(label)}${note ? ` <i>${esc(note)}</i>` : ""}</li>`;
  }).join("")}</ol>`;
}

// facts() picks the handful of values a reader needs first. The layout depends on the signer kind.
function facts(s) {
  const e = s.enrollment ?? {}, t = s.transparency ?? {}, m = s.manifest ?? {};
  const signedAt = s.valid_until ? day(s.valid_until - (e.max_age ?? 0)) : "";
  const f = [["Type", esc(e.type)], ["Manifest", m.version ? `${esc(m.version)} <span class="dim">· ${m.files} files</span>` : ""]];
  if (t.sigstore) {
    const x = t.sigstore.signers[0] ?? {}, r = t.sigstore.entries[0];
    const logged = r ? `${a(r.search_url ?? r.log_url, new URL(r.log_url ?? "https://x").hostname)} <span class="dim">· ${day(r.integrated_time)}</span>` : "";
    if (x.repo) {
      f.push(["Signed by", a(x.repo, repoName(x.repo))], ["Via", issuerName(x.issuer)], ["Ref", shortRef(x.ref)],
        ["Workflow", x.workflow ? a(x.workflow.file, x.workflow.file.split("/").pop()) : x.build_config ? a(x.build_config, repoName(x.build_config).split("@")[0].split("//").pop()) : esc(x.build_signer)],
        ["Run", x.run ? a(x.run, "#" + (x.run.split(/\/(runs|jobs|pipelines)\//)[2]?.split("/")[0] ?? x.run)) : ""]);
    } else if (x.identity_kind === "email") {
      f.push(["Signed by", esc(x.identity)], ["Via", issuerName(x.issuer)]);
    } else {
      f.push(["Identity", esc(x.identity ?? x.error)], ["Via", issuerName(x.issuer)]);
    }
    f.push(["Logged in", logged]);
  } else if (t.sigsum) {
    const r = t.sigsum[0] ?? {};
    f.push(["Signers", `${e.signers?.length ?? "?"} keys <span class="dim">· threshold ${e.threshold}</span>`],
      ["Logged in", r.log_url ? `${a(r.leaf_url, new URL(r.log_url).hostname)} <span class="dim">· leaf #${r.leaf_index}</span>` : ""],
      ["Witnesses", r.cosignatures], ["Signed", signedAt]);
  }
  f.push(["Expires", day(s.valid_until)]);
  return `<dl class="facts">${f.filter(([, v]) => v).map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`).join("")}</dl>`;
}

// detail() renders the expanded card: facts, checks, then collapsed sections.
function detail(s) {
  const e = s.enrollment ?? {}, t = s.transparency ?? {};
  let html = `<div class="top">${facts(s)}${checks(s)}</div>`;
  html += sub("Enrollment", dl([
    ["type", esc(e.type)], ["max_age", e.max_age ? `${Math.round(e.max_age / 86400)} days` : ""],
    ["list hash", short(s.enrollment_hash)], ["canonical key", code(s.canonical)],
    ["bundle used", s.bundle_used ? `${esc(s.bundle_used)} <span class="dim">(bundle.json ${esc(s.bundles?.current)}, bundle-prev.json ${esc(s.bundles?.previous)})</span>` : ""],
    ["signers", e.signers?.map((k) => short(k, 12)).join(" ")], ["threshold", e.threshold],
    ["logs", e.logs && Object.entries(e.logs).map(([k, u]) => `${a(u, new URL(u).hostname)} <span class="dim">key ${short(k, 8)}</span>`).join("<br>")],
    ["claims", e.claims && Object.entries(e.claims).map(([o, v]) => `${oid(o)} = <span class="dim">${esc(v)}</span>`).join("<br>")],
    ["error detail", s.detail ? `<span class="fail">${esc(s.detail)}</span>` : ""],
  ]));
  if (s.manifest) html += sub("Manifest", dl([
    ["name", esc(s.manifest.name)], ["version", esc(s.manifest.version)],
    ["files", `${s.manifest.files} (${s.manifest.wasm} wasm, ${s.manifest.extra_csp} extra CSP paths)`],
    ["default_csp", code(s.manifest.default_csp)], ["valid until", ts(s.valid_until)],
  ]));
  if (t.error) html += sub("Transparency", `<b class="fail">${esc(t.error)}</b>`);
  if (t.sigsum) {
    const total = t.sigsum.flatMap((r) => r.history ?? []).reduce((n, h) => n + h.leaves.length, 0);
    html += sub("Sigsum records", t.sigsum.map((r) => dl([
      ["signer key", short(r.signer, 12)], ["log", r.log_url ? a(r.log_url) : `<b class="warn">unknown</b> ${short(r.log_key_hash)}`],
      ["leaf", r.leaf_url ? a(r.leaf_url, `#${r.leaf_index}`) : r.leaf_index], ["tree size", r.tree_size], ["cosignatures", r.cosignatures],
      ["present in log", r.in_log === undefined ? "" : presence(r.in_log)], ["error", r.error && `<b class="fail">${esc(r.error)}</b>`],
    ])).join("<hr>"));
    html += sub(`Sigsum history <span class="dim">· ${total} leaves by this site's keys</span>`, `<p class="hint">Every leaf in the enrolled logs signed by this site's keys, from the daily log scan. A leaf is only a checksum, so signatures other than WEBCAT manifests may appear.</p>` +
      t.sigsum.map((r) => (r.history ?? []).map((h) => {
        const leaves = [...h.leaves].reverse();
        return dl([[new URL(h.log_url).hostname, leaves.length ? leaves.map(([i]) => a(`${h.log_url}/get-leaves/${i}/${i + 1}`, `#${i}`) + (i === r.leaf_index ? ' <b class="ok">current</b>' : "")).join(", ") : `<span class="dim">none of ${h.size.toLocaleString()} leaves</span>`]]);
      }).join("")).join("<hr>"));
  }
  if (t.sigstore) {
    html += sub("Sigstore signer", t.sigstore.signers.map((x) => dl([
      ["identity", `${esc(x.identity)} <span class="dim">(${esc(x.identity_kind)})</span>`], ["issuer", esc(x.issuer)],
      ["source repo", a(x.repo)], ["ref", esc(x.ref)],
      ["commit", x.sha && x.repo ? a(`${x.repo}/commit/${x.sha}`, x.sha.slice(0, 12)) : esc(x.sha)],
      ["build signer", esc(x.build_signer)], ["build config", esc(x.build_config)], ["run", a(x.run)], ["runner", esc(x.runner)], ["trigger", esc(x.trigger)],
      ["workflow links", x.workflow ? `${a(x.workflow.file, "file")} · ${a(x.workflow.runs, "all runs")}` : ""],
      ["cert issued", esc(x.not_before)], ["error", x.error && `<b class="fail">${esc(x.error)}</b>`],
    ])).join("<hr>"));
    const byHash = Object.entries(t.sigstore.by_hash).map(([k, v]) => [`${k} manifest`, v.error ? `<b class="fail">${esc(v.error)}</b>` : v.length ? v.map((x) => a(x.url, x.uuid.slice(0, 12) + "…")).join(", ") : "none"]);
    html += sub("Rekor entries", t.sigstore.entries.map((r) => dl([
      ["log", a(r.log_url, new URL(r.log_url ?? "https://x").hostname)], ["index", r.search_url ? a(r.search_url, r.log_index) : esc(r.log_index)],
      ["integrated", ts(r.integrated_time)], ["uuid", short(r.uuid, 12)], ["present in log", presence(r.found)], ["error", r.error && `<b class="fail">${esc(r.error)}</b>`],
    ])).join("<hr>") + `<hr>` + dl(byHash));
  }
  html += `<p class="tbds">${tbd("Chain history", "Enrollment changes on the WEBCAT chain (first enrollment, hash updates, removals) are not yet tracked; only the current verified list state is shown.")} ${t.sigstore ? tbd("Sigstore history", "Rekor has no search by signing identity; a full history needs the BigQuery mirror of Rekor or a log monitor.") : ""}</p>`;
  return html;
}

// signer() returns the short text for the list's signer column.
function signer(s) {
  const t = s.transparency ?? {};
  if (t.sigstore) return t.sigstore.signers.map((x) => x.repo ? repoName(x.repo) : x.identity ?? x.error ?? "").join(", ");
  if (t.sigsum) return [...new Set(t.sigsum.map((r) => r.log_url ? new URL(r.log_url).hostname : r.log_key_hash))].join(", ");
  return "";
}

function row(s, open) {
  const type = s.enrollment?.type ?? "";
  return `<details class="site" data-host="${esc(s.host)}"${open ? " open" : ""}>
<summary><span class="host">${a("https://" + s.host, s.host)}</span><span>${type ? `<span class="pill ${esc(type)}">${esc(type)}</span>` : ""}</span>
<span>${statusBadge(s)}</span>
<span class="dim" title="${esc(signer(s))}">${esc(signer(s))}</span><span class="dim" title="manifest signed">${day(s.signed_at)}</span></summary>
<div class="body">${open ? detail(s) : ""}</div></details>`;
}

// Load the data and render the header and stat tiles.
const data = await (await fetch("/data.json", { cache: "no-store" })).json();
const sites = data.sites.map((s) => ({ ...s, _text: JSON.stringify(s).toLowerCase() })); // _text backs the search box.
const count = (f) => sites.filter(f).length;
const logsLine = Object.entries(data.logs ?? {}).filter(([k]) => k !== "error").map(([u, l]) => `${a(u, new URL(u).hostname)} ${l.size.toLocaleString()} leaves`).join(" · ");
$("meta").innerHTML = `block <b title="${esc(data.block.time)}">${esc(data.block.height)}</b> · ${code(data.block.chain_id)} · ${esc(data.block.signed_power)} validators · built ${esc(data.generated_at.slice(0, 16).replace("T", " "))} UTC${logsLine ? ` · Sigsum: ${logsLine}` : ""}${data.logs?.error ? ` · <b class="fail">Sigsum scan failed: ${esc(data.logs.error)}</b>` : ""}
<details><summary>hashes</summary><div>app_hash ${code(data.block.app_hash)}<br>canonical root ${code(data.block.canonical_root_hash)}</div></details>`;
$("stats").innerHTML = [[sites.length, "enrolled sites", ""], [count((s) => !s.error), "verifying", "ok"], [count((s) => s.error), "failing", "fail"],
  [`${count((s) => s.enrollment?.type === "sigsum")} / ${count((s) => s.enrollment?.type === "sigstore")}`, "sigsum / sigstore", ""],
  [sites.flatMap((s) => s.transparency?.sigsum ?? []).flatMap((r) => r.history ?? []).reduce((acc, h) => acc + h.leaves.length, 0), "sigsum leaves by enrolled keys", ""]]
  .map(([v, l, c]) => `<div class="stat"><b class="${c}">${v}</b><span>${l}</span></div>`).join("");

// The URL holds the view state: search, filters, sort, and open cards.
const params = new URLSearchParams(location.search);
const state = { q: params.get("q") ?? "", type: params.get("type") ?? "", status: params.get("status") ?? "", sort: params.get("sort") ?? "updated", dir: params.get("dir") ?? "desc", page: 0, open: new Set(params.getAll("host")) };
const SORT = { host: (s) => s.host, type: (s) => s.enrollment?.type ?? "~", status: (s) => (s.error ? "1" + statusLabel(s) : "0"), signer: (s) => signer(s) || "~", updated: (s) => s.signed_at ?? 0 };
$("q").value = state.q;

// sync() writes the view state back to the URL.
function sync() {
  const p = new URLSearchParams();
  if (state.q) p.set("q", state.q);
  if (state.type) p.set("type", state.type);
  if (state.status) p.set("status", state.status);
  if (state.sort !== "updated" || state.dir !== "desc") { p.set("sort", state.sort); p.set("dir", state.dir); }
  for (const h of state.open) p.append("host", h);
  history.replaceState(null, "", p.size ? "?" + p : location.pathname);
}

// render() filters, sorts, pages, and draws the list.
function render() {
  const needle = state.q.trim().toLowerCase();
  const key = SORT[state.sort] ?? SORT.updated, m = state.dir === "asc" ? 1 : -1;
  const hits = sites.filter((s) => (!needle || s._text.includes(needle)) && (!state.type || s.enrollment?.type === state.type) && (!state.status || (state.status === "ok") === !s.error));
  hits.sort((x, y) => { const a = key(x), b = key(y); return (a < b ? -1 : a > b ? 1 : 0) * m || x.host.localeCompare(y.host); });
  for (const b of $("head").children) { b.classList.toggle("on", b.dataset.k === state.sort); b.dataset.dir = b.dataset.k === state.sort ? state.dir : ""; }
  const pages = Math.max(1, Math.ceil(hits.length / PAGE));
  const first = hits.findIndex((s) => state.open.has(s.host));
  if (first >= 0 && state.page === -1) state.page = Math.floor(first / PAGE); // On load, jump to the first open card.
  state.page = Math.min(Math.max(state.page, 0), pages - 1);
  const slice = hits.slice(state.page * PAGE, state.page * PAGE + PAGE);
  $("list").innerHTML = slice.map((s) => row(s, state.open.has(s.host))).join("") || `<p class="empty">No sites match.</p>`;
  $("pager").innerHTML = `<span>${hits.length} sites</span>` + Array.from({ length: pages }, (_, i) => `<button class="btn${i === state.page ? " on" : ""}" data-p="${i}">${i + 1}</button>`).join("");
  for (const g of ["type", "status"]) for (const b of $("f-" + g).children) b.classList.toggle("on", b.dataset.v === state[g]);
  sync();
}

$("q").addEventListener("input", () => { state.q = $("q").value; state.page = 0; render(); });
for (const g of ["type", "status"]) $("f-" + g).addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return; state[g] = b.dataset.v; state.page = 0; render(); });
$("head").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (!b) return; if (state.sort === b.dataset.k) state.dir = state.dir === "asc" ? "desc" : "asc"; else { state.sort = b.dataset.k; state.dir = b.dataset.k === "updated" ? "desc" : "asc"; } state.page = 0; render(); });
$("pager").addEventListener("click", (ev) => { const b = ev.target.closest("button"); if (b) { state.page = Number(b.dataset.p); render(); } });
$("list").addEventListener("toggle", (ev) => {
  const d = ev.target;
  if (d.open) { state.open.add(d.dataset.host); d.querySelector(".body").innerHTML = detail(sites.find((s) => s.host === d.dataset.host)); }
  else state.open.delete(d.dataset.host);
  sync();
}, true);
state.page = -1; // -1 asks render() to pick the page of the first open card.
render();
