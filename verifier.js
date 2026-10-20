// Charter attestation verifier: decode an EAS attestation on Base or Base Sepolia, then
// recompute the sha256 of every text it names. No dependency, runs in the browser and in Node 20.

export const EAS = "0x4200000000000000000000000000000000000021";
export const NETWORKS = {
  base: { chainId: 8453, rpc: "https://mainnet.base.org" },
  "base-sepolia": { chainId: 84532, rpc: "https://sepolia.base.org" },
};
export const SCHEMA = "string version,string date,string[] names,bytes32[] digests,string[] cids";

const SELECTOR_GET_ATTESTATION = "0xa3112a64";
const ZERO_UID = "0x" + "00".repeat(32);

function bytesOf(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) throw new Error("odd length hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function hexOf(bytes) {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function word(bytes, index) {
  const start = index * 32;
  if (start + 32 > bytes.length) throw new Error("read past the end of the data");
  let value = 0n;
  for (let i = 0; i < 32; i += 1) value = (value << 8n) | BigInt(bytes[start + i]);
  return value;
}

function sliceAt(bytes, offset, length) {
  if (offset + length > bytes.length) throw new Error("read past the end of the data");
  return bytes.slice(offset, offset + length);
}

function decodeString(bytes, offset) {
  const length = Number(word(bytes, offset / 32));
  return new TextDecoder().decode(sliceAt(bytes, offset + 32, length));
}

function decodeStringArray(bytes, offset) {
  const count = Number(word(bytes, offset / 32));
  const values = [];
  for (let i = 0; i < count; i += 1) {
    const relative = Number(word(bytes, (offset + 32 + i * 32) / 32));
    values.push(decodeString(bytes, offset + 32 + relative));
  }
  return values;
}

function decodeBytes32Array(bytes, offset) {
  const count = Number(word(bytes, offset / 32));
  const values = [];
  for (let i = 0; i < count; i += 1) {
    values.push("0x" + hexOf(sliceAt(bytes, offset + 32 + i * 32, 32)));
  }
  return values;
}

function decodeBytes(bytes, offset) {
  const length = Number(word(bytes, offset / 32));
  return sliceAt(bytes, offset + 32, length);
}

// string version,string date,string[] names,bytes32[] digests,string[] cids
export function decodeCharterData(dataHex) {
  const bytes = bytesOf(dataHex);
  const heads = [0, 1, 2, 3, 4].map((index) => Number(word(bytes, index)));
  const version = decodeString(bytes, heads[0]);
  const date = decodeString(bytes, heads[1]);
  const names = decodeStringArray(bytes, heads[2]);
  const digests = decodeBytes32Array(bytes, heads[3]).map((digest) => digest.toLowerCase());
  const cids = decodeStringArray(bytes, heads[4]);
  if (names.length !== digests.length || names.length !== cids.length) {
    throw new Error("names, digests and cids are not parallel");
  }
  return { version, date, names, digests, cids };
}

// The EAS Attestation struct returned by getAttestation(bytes32).
export function decodeAttestation(dataHex) {
  const bytes = bytesOf(dataHex);
  const uid = "0x" + hexOf(sliceAt(bytes, 0, 32));
  const schema = "0x" + hexOf(sliceAt(bytes, 32, 32));
  const time = Number(word(bytes, 2));
  const expirationTime = Number(word(bytes, 3));
  const revocationTime = Number(word(bytes, 4));
  const refUID = "0x" + hexOf(sliceAt(bytes, 5 * 32, 32));
  const recipient = "0x" + hexOf(sliceAt(bytes, 6 * 32, 32)).slice(24);
  const attester = "0x" + hexOf(sliceAt(bytes, 7 * 32, 32)).slice(24);
  const revocable = word(bytes, 8) !== 0n;
  const dataOffset = Number(word(bytes, 9));
  const data = "0x" + hexOf(decodeBytes(bytes, dataOffset));
  return { uid, schema, time, expirationTime, revocationTime, refUID, recipient, attester, revocable, data };
}

async function sha256(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return "0x" + hexOf(new Uint8Array(digest));
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (typeof value === "string") return bytesOf(value);
  throw new Error("the text fetch did not return bytes");
}

function padUid(uid) {
  const clean = (uid || "").toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(clean)) throw new Error("the uid must be 32 bytes of hex");
  return clean;
}

export async function verifyCharter({ uid, network, rpc, ipfs }) {
  const report = { ok: false, attestation: null, texts: [] };
  const chain = NETWORKS[network] ? network : "base";
  const registry = EAS;

  let call;
  try {
    const padded = padUid(uid);
    const result = await rpc("eth_call", [{ to: registry, data: SELECTOR_GET_ATTESTATION + padded }, "latest"]);
    call = typeof result === "string" ? result : result?.data ?? "0x";
  } catch (error) {
    report.reason = `the RPC call failed: ${error?.message ?? error}`;
    return report;
  }

  if (!call || call === "0x" || call.length < 2 + 32 * 10) {
    report.reason = `no attestation with that uid on ${chain}`;
    return report;
  }

  let attestation;
  let charter;
  try {
    attestation = decodeAttestation(call);
    if (attestation.uid === ZERO_UID) {
      report.reason = `no attestation with that uid on ${chain}`;
      return report;
    }
    charter = decodeCharterData(attestation.data);
  } catch (error) {
    report.reason = `the attestation data could not be read: ${error?.message ?? error}`;
    return report;
  }

  const revoked = attestation.revocationTime > 0;
  report.attestation = {
    uid: attestation.uid,
    attester: attestation.attester,
    time: attestation.time,
    revoked,
  };

  for (let i = 0; i < charter.names.length; i += 1) {
    const name = charter.names[i];
    const cid = charter.cids[i];
    const expected = charter.digests[i];
    const entry = { name, cid, expected, actual: null, match: false };
    try {
      const bytes = toBytes(await ipfs(cid));
      entry.actual = await sha256(bytes);
      entry.match = entry.actual === expected;
    } catch (error) {
      entry.error = `the text could not be read: ${error?.message ?? error}`;
    }
    report.texts.push(entry);
  }

  if (revoked) {
    report.reason = "the attestation was revoked";
    return report;
  }

  const failed = report.texts.filter((text) => !text.match);
  if (failed.length > 0) {
    const names = failed.map((text) => text.name).join(", ");
    report.reason = `the texts do not match the attestation: ${names}`;
    return report;
  }

  report.ok = true;
  return report;
}
