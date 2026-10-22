// verifier.js — Founding Charter attestation verifier (EAS on Base / Base Sepolia)
// No dependencies. Runs in the browser (ES module) and in Node 20+.

export const EAS_ADDRESS = '0x4200000000000000000000000000000000000021';
export const EAS_CHAIN = { base: 8453, 'base-sepolia': 84532 };
export const CHARTER_SCHEMA =
  'string version,string date,string[] names,bytes32[] digests,string[] cids';
// keccak256("getAttestation(bytes32)")[:4]
export const GET_ATTESTATION_SELECTOR = '0xa3112a64';

/* ------------------------------- hex helpers ------------------------------ */

export function strip0x(h) {
  return typeof h === 'string' && h.startsWith('0x') ? h.slice(2) : String(h || '');
}

export function hexToBytes(h) {
  const s = strip0x(h);
  if (s.length % 2 !== 0) throw new Error('hex string has an odd length');
  if (!/^[0-9a-fA-F]*$/.test(s)) throw new Error('not a hex string');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function word(hex, index) {
  const start = index * 64;
  if (hex.length < start + 64) throw new Error(`ABI data is too short for word ${index}`);
  return hex.slice(start, start + 64);
}

function wordToNumber(w) {
  return Number(BigInt('0x' + w));
}

function decodeStringAt(hex, byteOffset) {
  const base = byteOffset * 2;
  const len = wordToNumber(hex.slice(base, base + 64));
  const body = hex.slice(base + 64, base + 64 + len * 2);
  if (body.length !== len * 2) throw new Error('ABI string runs past the end of the data');
  return new TextDecoder().decode(hexToBytes(body));
}

/* --------------------------- Charter data decoding ------------------------ */

/**
 * Decode the `data` field of a Founding Charter attestation.
 * Schema: string version,string date,string[] names,bytes32[] digests,string[] cids
 */
export function decodeCharterData(dataHex) {
  const hex = strip0x(dataHex).toLowerCase();
  if (!hex) throw new Error('charter data is empty');
  const oVersion = wordToNumber(word(hex, 0));
  const oDate = wordToNumber(word(hex, 1));
  const oNames = wordToNumber(word(hex, 2));
  const oDigests = wordToNumber(word(hex, 3));
  const oCids = wordToNumber(word(hex, 4));

  const version = decodeStringAt(hex, oVersion);
  const date = decodeStringAt(hex, oDate);
  const names = decodeStringArray(hex, oNames);
  const digests = decodeBytes32Array(hex, oDigests).map((d) => '0x' + d);
  const cids = decodeStringArray(hex, oCids);

  if (names.length !== digests.length || names.length !== cids.length) {
    throw new Error(
      `charter arrays are not parallel: ${names.length} names, ${digests.length} digests, ${cids.length} cids`
    );
  }
  return { version, date, names, digests, cids };
}

function decodeStringArray(hex, byteOffset) {
  const base = byteOffset * 2;
  const count = wordToNumber(hex.slice(base, base + 64));
  const out = [];
  for (let i = 0; i < count; i++) {
    const rel = wordToNumber(hex.slice(base + 64 + i * 64, base + 128 + i * 64));
    // element offsets are relative to the start of the array payload (after count)
    out.push(decodeStringAt(hex, byteOffset + 32 + rel));
  }
  return out;
}

function decodeBytes32Array(hex, byteOffset) {
  const base = byteOffset * 2;
  const count = wordToNumber(hex.slice(base, base + 64));
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push(hex.slice(base + 64 + i * 64, base + 128 + i * 64));
  }
  return out;
}

/* ---------------------------- attestation decoding ------------------------ */

/** ABI-encode a getAttestation(bytes32) eth_call payload. */
export function encodeGetAttestation(uid) {
  const u = strip0x(uid).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(u)) throw new Error('uid must be 32 bytes of hex');
  return GET_ATTESTATION_SELECTOR + u;
}

/**
 * Decode the EAS Attestation struct returned by getAttestation:
 * (bytes32 uid, bytes32 schema, uint64 time, uint64 expirationTime,
 *  uint64 revocationTime, bytes32 refUID, address recipient, address attester,
 *  bool revocable, bytes data)
 *
 * Base's EAS returns the struct behind a leading offset word (0x20…), so both
 * shapes are accepted: inline, and pointer-to-struct.
 */
export function decodeAttestation(resultHex) {
  const hex = strip0x(resultHex).toLowerCase();
  if (!hex) return null;
  const words = Math.floor(hex.length / 64);
  if (words < 10) return null;

  let baseWord = 0;
  const first = Number(BigInt('0x' + hex.slice(0, 64)));
  if (first !== 0 && first % 32 === 0 && first <= 1024 && words * 32 > first) {
    baseWord = first / 32; // tuple is behind a pointer
  }
  if (words < baseWord + 10) return null;

  const w = (i) => word(hex, baseWord + i);
  const uid = '0x' + w(0);
  if (/^0x0+$/.test(uid)) return null; // zeroed struct = no attestation
  const schema = '0x' + w(1);
  const time = wordToNumber(w(2));
  const expirationTime = wordToNumber(w(3));
  const revocationTime = wordToNumber(w(4));
  const refUID = '0x' + w(5);
  const recipient = '0x' + w(6).slice(24);
  const attester = '0x' + w(7).slice(24);
  const revocable = wordToNumber(w(8)) !== 0;
  const oData = wordToNumber(w(9));
  // data offset is relative to the start of the struct
  const dataStart = (baseWord * 32 + oData) * 2;
  if (dataStart + 64 > hex.length) return null;
  const len = wordToNumber(hex.slice(dataStart, dataStart + 64));
  const data = hex.slice(dataStart + 64, dataStart + 64 + len * 2);
  return {
    uid, schema, time, expirationTime, revocationTime, refUID,
    recipient, attester, revocable,
    revoked: revocationTime !== 0,
    data: '0x' + data,
  };
}

/* ------------------------------- hashing --------------------------------- */

export async function sha256Hex(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (subtle) {
    const digest = await subtle.digest('SHA-256', view);
    return bytesToHex(new Uint8Array(digest));
  }
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(view).digest('hex');
}

/* ------------------------------- verifier -------------------------------- */

/**
 * Verify that the on-chain charter attestation matches its published texts.
 * @param {{uid:string, network:'base'|'base-sepolia', rpc:Function, ipfs:Function}} opts
 *   rpc(method, params) -> Promise<result>; ipfs(cid) -> Promise<Uint8Array>
 */
export async function verifyCharter({ uid, network, rpc, ipfs }) {
  const chainId = EAS_CHAIN[network];
  if (!chainId) throw new Error(`unknown network "${network}" (expected base or base-sepolia)`);
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(uid || ''))) {
    throw new Error('uid must be a 0x-prefixed 32 byte hex string');
  }
  if (typeof rpc !== 'function') throw new Error('rpc must be a function');
  if (typeof ipfs !== 'function') throw new Error('ipfs must be a function');

  const result = await rpc('eth_call', [
    { to: EAS_ADDRESS, data: encodeGetAttestation(uid) },
    'latest',
  ]);

  const attestation = decodeAttestation(result);
  if (!attestation) {
    return { ok: false, reason: 'no attestation with that uid on this network', attestation: null, texts: [] };
  }

  let charter;
  try {
    charter = decodeCharterData(attestation.data);
  } catch (err) {
    return {
      ok: false,
      reason: `attestation data is not a charter: ${err.message}`,
      attestation: pickAttestation(attestation),
      texts: [],
    };
  }

  const texts = [];
  for (let i = 0; i < charter.names.length; i++) {
    const name = charter.names[i];
    const cid = charter.cids[i];
    const expected = String(charter.digests[i]).toLowerCase();
    try {
      const bytes = await ipfs(cid);
      const actual = '0x' + (await sha256Hex(bytes));
      texts.push({
        name, cid, expected, actual,
        match: actual === expected,
        ...(actual === expected ? {} : { error: 'sha256 does not match the attested digest' }),
      });
    } catch (err) {
      texts.push({
        name, cid, expected, actual: null, match: false,
        error: `text could not be fetched and hashed: ${err && err.message ? err.message : String(err)}`,
      });
    }
  }

  const allMatch = texts.length > 0 && texts.every((t) => t.match);
  if (attestation.revoked) {
    return { ok: false, reason: 'attestation is revoked', attestation: pickAttestation(attestation), texts };
  }
  if (!allMatch) {
    const bad = texts.filter((t) => !t.match).map((t) => t.name);
    return {
      ok: false,
      reason: `mismatch for: ${bad.join(', ') || 'no texts'}`,
      attestation: pickAttestation(attestation),
      texts,
    };
  }
  return { ok: true, attestation: pickAttestation(attestation), texts, version: charter.version, date: charter.date };
}

function pickAttestation(a) {
  return {
    uid: a.uid, attester: a.attester, time: a.time,
    revoked: a.revoked, schema: a.schema, recipient: a.recipient,
  };
}

/* ------------------------- ready-made transports ------------------------- */

export const PUBLIC_RPC = {
  base: 'https://mainnet.base.org',
  'base-sepolia': 'https://sepolia.base.org',
};

export function jsonRpc(rpcUrl) {
  return async function rpc(method, params) {
    const res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    if (!res.ok) throw new Error(`RPC answered ${res.status}`);
    const body = await res.json();
    if (body.error) throw new Error(`RPC error: ${body.error.message || JSON.stringify(body.error)}`);
    return body.result;
  };
}

export function ipfsGateway(gateway) {
  const base = String(gateway || 'https://ipfs.io/ipfs/').replace(/\/+$/, '/');
  return async function ipfs(cid) {
    const url = `${base}${cid}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`IPFS gateway answered ${res.status}`);
    return new Uint8Array(await res.arrayBuffer());
  };
}
