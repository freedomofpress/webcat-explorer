// This module scans Sigsum logs incrementally.
// It walks each log from the last scanned index and keeps every leaf signed by an enrolled key.
// A JSON state file holds the cursor and the matches, so CI can cache it. A missing file triggers a full scan.
import { mkdir, readFile, writeFile } from "node:fs/promises";

// scanLogs takes a Map<logUrl, Set<signerKeyHashHex>> and returns { [logUrl]: { size, leaves } }.
export async function scanLogs(wanted, statePath) {
  let state = {};
  try { state = JSON.parse(await readFile(statePath)); } catch {}
  const out = {};
  for (const [url, keys] of wanted) {
    const st = state[url] ?? { scanned: 0, keys: [], leaves: {} };
    // A new signer key invalidates the cursor. The scan restarts from index 0 for this log.
    if ([...keys].some((k) => !st.keys.includes(k))) { st.scanned = 0; st.leaves = {}; }
    st.keys = [...new Set([...st.keys, ...keys])];
    const head = await (await fetch(`${url}/get-tree-head`, { signal: AbortSignal.timeout(20000) })).text();
    const size = Number(/^size=(\d+)/m.exec(head)?.[1]);
    let i = st.scanned, requests = 0;
    // Each log caps get-leaves at its own batch size and returns fewer leaves than requested.
    while (i < size) {
      const r = await fetch(`${url}/get-leaves/${i}/${Math.min(i + 4096, size)}`, { signal: AbortSignal.timeout(60000) });
      if (!r.ok) throw new Error(`${r.status} ${url} get-leaves/${i}: ${await r.text()}`);
      const lines = (await r.text()).split("\n").filter((l) => l.startsWith("leaf="));
      if (lines.length === 0) throw new Error(`${url} returned no leaves at ${i}`);
      lines.forEach((l, j) => {
        const [checksum, , keyHash] = l.slice(5).split(" ");
        if (st.keys.includes(keyHash)) (st.leaves[keyHash] ??= []).push([i + j, checksum]);
      });
      i += lines.length;
      requests++;
    }
    st.scanned = size;
    state[url] = st;
    out[url] = { size, leaves: st.leaves };
    console.log(`scanned ${url}: size ${size}, ${requests} requests, ${Object.values(st.leaves).flat().length} matching leaves`);
  }
  await mkdir(new URL(".", statePath), { recursive: true });
  await writeFile(statePath, JSON.stringify(state));
  return out;
}
