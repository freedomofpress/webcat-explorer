// This self-check runs offline. It fails if the ported helpers drift from the extension's behavior.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { canonicalize, enrollmentHash, extractHostname, extractRawHash, hex } from "./verify.mjs";

assert.equal(canonicalize({ b: 1, a: [true, null, 'x"y\\z'], c: { z: "", y: -2 } }), '{"a":[true,null,"x\\"y\\\\z"],"b":1,"c":{"y":-2,"z":""}}');
assert.equal(canonicalize({ f: 1.5 }), null);
assert.equal(extractHostname("canonical/.com.legoktm.git"), "git.legoktm.com");
assert.equal(hex(extractRawHash("0a20" + "ab".repeat(32))), "ab".repeat(32));
assert.throws(() => extractRawHash("0b20" + "ab".repeat(32)));
assert.equal(await enrollmentHash({ b: 2, a: 1 }), createHash("sha256").update('{"a":1,"b":2}').digest("hex"));
console.log("ok");
