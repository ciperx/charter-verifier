import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { decodeCharterData, decodeAttestation, verifyCharter, EAS, NETWORKS } from "../verifier.js";

const fixture = JSON.parse(await readFile(new URL("../fixtures/charter.json", import.meta.url), "utf8"));
const textBytes = new Map(fixture.texts.map((text) => [text.cid, Uint8Array.from(Buffer.from(text.content_base64, "base64"))]));

function rpcReturning(hex) {
  const calls = [];
  const rpc = async (method, params) => {
    calls.push({ method, params });
    return hex;
  };
  return { rpc, calls };
}

function ipfsFrom(map, mutate) {
  const seen = [];
  const ipfs = async (cid) => {
    seen.push(cid);
    if (!map.has(cid)) throw new Error("gateway timeout");
    const bytes = map.get(cid);
    if (mutate && mutate.cid === cid) {
      const copy = new Uint8Array(bytes);
      copy[0] = copy[0] ^ 0xff;
      return copy;
    }
    return bytes;
  };
  return { ipfs, seen };
}

test("A1 decodeCharterData reads back what the schema encodes", () => {
  const decoded = decodeAttestation(fixture.attestation);
  const charter = decodeCharterData(decoded.data);
  assert.equal(charter.version, fixture.version);
  assert.equal(charter.date, fixture.date);
  assert.deepEqual(charter.names, fixture.texts.map((text) => text.name));
  assert.deepEqual(charter.cids, fixture.texts.map((text) => text.cid));
  assert.deepEqual(charter.digests, fixture.expected_digests);
  for (const digest of charter.digests) assert.match(digest, /^0x[0-9a-f]{64}$/);
});

test("A2 a matching attestation shows a match for each text and ok true", async () => {
  const { rpc } = rpcReturning(fixture.attestation);
  const { ipfs } = ipfsFrom(textBytes);
  const report = await verifyCharter({ uid: fixture.uid, network: "base", rpc, ipfs });
  assert.equal(report.ok, true, report.reason);
  assert.equal(report.texts.length, 3);
  for (const text of report.texts) {
    assert.equal(text.match, true);
    assert.equal(text.actual, text.expected);
  }
  assert.equal(report.attestation.revoked, false);
  assert.match(report.attestation.attester, /^0x[0-9a-f]{40}$/);
});

test("A3 a tampered text shows a mismatch for that text only, with both digests, and ok false", async () => {
  const { rpc } = rpcReturning(fixture.attestation);
  const soul = fixture.texts.find((text) => text.name === "soul");
  const { ipfs } = ipfsFrom(textBytes, { cid: soul.cid });
  const report = await verifyCharter({ uid: fixture.uid, network: "base", rpc, ipfs });
  assert.equal(report.ok, false);
  const bad = report.texts.filter((text) => !text.match);
  assert.equal(bad.length, 1);
  assert.equal(bad[0].name, "soul");
  assert.match(bad[0].expected, /^0x[0-9a-f]{64}$/);
  assert.match(bad[0].actual, /^0x[0-9a-f]{64}$/);
  assert.notEqual(bad[0].expected, bad[0].actual);
  assert.match(report.reason, /soul/);
});

test("A4 an unknown UID, a revoked attestation and a text that cannot be fetched are reported, never thrown", async () => {
  const unknown = await verifyCharter({ uid: fixture.uid, network: "base", rpc: rpcReturning("0x").rpc, ipfs: ipfsFrom(textBytes).ipfs });
  assert.equal(unknown.ok, false);
  assert.match(unknown.reason, /no attestation/);
  assert.deepEqual(unknown.texts, []);

  const reverting = await verifyCharter({
    uid: fixture.uid,
    network: "base",
    rpc: async () => {
      throw new Error("execution reverted: none");
    },
    ipfs: ipfsFrom(textBytes).ipfs,
  });
  assert.equal(reverting.ok, false);
  assert.match(reverting.reason, /RPC call failed/);

  const revoked = await verifyCharter({
    uid: fixture.uid,
    network: "base",
    rpc: rpcReturning(fixture.revoked_attestation).rpc,
    ipfs: ipfsFrom(textBytes).ipfs,
  });
  assert.equal(revoked.ok, false);
  assert.match(revoked.reason, /revoked/);

  const missing = new Map(textBytes);
  missing.delete(fixture.texts[1].cid);
  const partial = await verifyCharter({
    uid: fixture.uid,
    network: "base",
    rpc: rpcReturning(fixture.attestation).rpc,
    ipfs: ipfsFrom(missing).ipfs,
  });
  assert.equal(partial.ok, false);
  const failed = partial.texts.find((text) => text.name === fixture.texts[1].name);
  assert.match(failed.error, /could not be read/);
  assert.equal(failed.match, false);
});

test("A5 works on Base and Base Sepolia, the network choosing the chain and the RPC", async () => {
  assert.equal(NETWORKS.base.chainId, 8453);
  assert.equal(NETWORKS["base-sepolia"].chainId, 84532);
  for (const network of ["base", "base-sepolia"]) {
    const { rpc, calls } = rpcReturning(fixture.attestation);
    const report = await verifyCharter({ uid: fixture.uid, network, rpc, ipfs: ipfsFrom(textBytes).ipfs });
    assert.equal(report.ok, true, `${network}: ${report.reason}`);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].method, "eth_call");
    assert.equal(calls[0].params[0].to, EAS);
    assert.equal(calls[0].params[0].data, `0xa3112a64${fixture.uid.slice(2)}`);
  }
});

test("A6 the page is mobile friendly and the Sepolia rehearsal fixture verifies end to end", async () => {
  const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1"/);
  assert.match(html, /max-width/);
  assert.match(html, /id="network"/);
  assert.match(html, /base-sepolia/);

  const { rpc } = rpcReturning(fixture.attestation);
  const report = await verifyCharter({ uid: fixture.uid, network: "base-sepolia", rpc, ipfs: ipfsFrom(textBytes).ipfs });
  assert.equal(report.ok, true);
  assert.equal(report.attestation.uid, fixture.uid);
});
