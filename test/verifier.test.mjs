import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  decodeCharterData, decodeAttestation, encodeGetAttestation,
  verifyCharter, sha256Hex, GET_ATTESTATION_SELECTOR, EAS_ADDRESS,
} from '../verifier.js';

/* ------------------------- tiny ABI encoder (test only) ------------------- */

const pad = (hex) => hex.padStart(64, '0');
const encStr = (s) => {
  const body = Buffer.from(s, 'utf8').toString('hex');
  return pad((body.length / 2).toString(16)) + body.padEnd(Math.ceil(body.length / 64) * 64, '0');
};
const wrapAt = (offsetWords, payloadHex) => pad((offsetWords * 32).toString(16)) + payloadHex;

function encodeStringArray(items) {
  let out = pad(items.length.toString(16));
  const heads = [];
  const bodies = [];
  let running = items.length * 32;
  for (const it of items) {
    const b = encStr(it);
    heads.push(pad(running.toString(16)));
    bodies.push(b);
    running += b.length / 2;
  }
  return out + heads.join('') + bodies.join('');
}

function encodeBytes32Array(items) {
  return pad(items.length.toString(16)) + items.map((d) => d.replace(/^0x/, '')).join('');
}

/** Encode charter data in schema order with head/tail offsets. */
export function encodeCharterData({ version, date, names, digests, cids }) {
  const parts = [encStr(version), encStr(date), encodeStringArray(names), encodeBytes32Array(digests), encodeStringArray(cids)];
  let running = parts.length * 32;
  const head = [];
  for (const p of parts) {
    head.push(pad(running.toString(16)));
    running += p.length / 2;
  }
  return '0x' + head.join('') + parts.join('');
}

function encodeAttestation(a) {
  const data = a.data.replace(/^0x/, '');
  const fixed = [
    a.uid.replace(/^0x/, ''),
    '11'.repeat(32),
    pad(a.time.toString(16)),
    '00'.repeat(32),
    pad((a.revocationTime || 0).toString(16)),
    '00'.repeat(32),
    pad(a.recipient.replace(/^0x/, '').toLowerCase().padStart(40, '0')),
    pad(a.attester.replace(/^0x/, '').toLowerCase().padStart(40, '0')),
    pad('1'),
    pad((10 * 32).toString(16)),
  ].join('');
  return '0x' + fixed + pad((data.length / 2).toString(16)) + data.padEnd(Math.ceil(data.length / 64) * 64, '0');
}

/* --------------------------------- fixtures ------------------------------ */

const texts = { 'bafy-charter': 'the founding charter of the realm\n', 'bafy-constitution': 'constitution text\n', 'bafy-soul': 'soul text\n' };
const digests = Object.values(texts).map((t) => '0x' + createHash('sha256').update(Buffer.from(t, 'utf8')).digest('hex'));
const charter = {
  version: '1', date: '2026-10-22',
  names: ['charter', 'constitution', 'soul'],
  digests,
  cids: Object.keys(texts),
};
const UID = '0x' + 'ab'.repeat(32);
const ATTESTER = '0x' + 'cd'.repeat(20);

function fixtures({ tamperSoul = false, revoked = false } = {}) {
  const calls = [];
  const rpc = async (method, params) => {
    calls.push({ method, params });
    const ret = encodeAttestation({ uid: UID, time: 1760000000, revocationTime: revoked ? 1760000100 : 0, recipient: '0x' + '00'.repeat(20), attester: ATTESTER, data: encodeCharterData(charter) });
    return ret;
  };
  const ipfs = async (cid) => {
    const t = texts[cid];
    if (!t) throw new Error('gateway 504');
    return new Uint8Array(Buffer.from(tamperSoul && cid === 'bafy-soul' ? 'tampered\n' : t, 'utf8'));
  };
  return { rpc, ipfs, calls };
}

/* ---------------------------------- tests -------------------------------- */

test('A1 decodeCharterData reads back what the schema encodes', () => {
  const d = decodeCharterData(encodeCharterData(charter));
  assert.equal(d.version, '1');
  assert.equal(d.date, '2026-10-22');
  assert.deepEqual(d.names, ['charter', 'constitution', 'soul']);
  assert.deepEqual(d.cids, ['bafy-charter', 'bafy-constitution', 'bafy-soul']);
  assert.equal(d.digests.length, 3);
  for (const dg of d.digests) assert.match(dg, /^0x[0-9a-f]{64}$/);
  assert.deepEqual(d.digests, digests);
});

test('A1b encodeGetAttestation uses the EAS selector and 32 byte uid', () => {
  const data = encodeGetAttestation(UID);
  assert.equal(data.slice(0, 10), GET_ATTESTATION_SELECTOR);
  assert.equal(data.slice(10), UID.slice(2));
  assert.equal(EAS_ADDRESS.length, 42);
});

test('A2 a matching attestation shows a match per text and ok true', async () => {
  const f = fixtures();
  const r = await verifyCharter({ uid: UID, network: 'base', rpc: f.rpc, ipfs: f.ipfs });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.attestation.attester, ATTESTER);
  assert.equal(r.texts.length, 3);
  for (const t of r.texts) { assert.equal(t.match, true); assert.equal(t.actual, t.expected); }
  // the call goes to EAS with eth_call
  assert.equal(f.calls[0].method, 'eth_call');
  assert.equal(f.calls[0].params[0].to, EAS_ADDRESS);
});

test('A3 a tampered text shows a mismatch for that text only', async () => {
  const f = fixtures({ tamperSoul: true });
  const r = await verifyCharter({ uid: UID, network: 'base', rpc: f.rpc, ipfs: f.ipfs });
  assert.equal(r.ok, false);
  const soul = r.texts.find((t) => t.name === 'soul');
  assert.equal(soul.match, false);
  assert.notEqual(soul.actual, soul.expected);
  assert.equal(r.texts.filter((t) => t.match).length, 2);
  assert.match(r.reason, /soul/);
});

test('A3b one unreadable text is reported, not thrown', async () => {
  const f = fixtures();
  const ipfs = async (cid) => { if (cid === 'bafy-constitution') throw new Error('gateway 504'); return f.ipfs(cid); };
  const r = await verifyCharter({ uid: UID, network: 'base', rpc: f.rpc, ipfs });
  assert.equal(r.ok, false);
  const t = r.texts.find((x) => x.name === 'constitution');
  assert.equal(t.match, false);
  assert.equal(t.actual, null);
  assert.match(t.error, /504/);
});

test('A4 a missing attestation is reported, not thrown', async () => {
  const r = await verifyCharter({ uid: UID, network: 'base', rpc: async () => '0x', ipfs: async () => new Uint8Array() });
  assert.equal(r.ok, false);
  assert.equal(r.attestation, null);
  assert.match(r.reason, /no attestation/);
});

test('A4b a zeroed struct counts as missing', () => {
  assert.equal(decodeAttestation('0x' + '00'.repeat(320)), null);
  assert.equal(decodeAttestation('0x'), null);
});

test('A5 a revoked attestation is reported as not ok', async () => {
  const f = fixtures({ revoked: true });
  const r = await verifyCharter({ uid: UID, network: 'base', rpc: f.rpc, ipfs: f.ipfs });
  assert.equal(r.ok, false);
  assert.equal(r.attestation.revoked, true);
  assert.match(r.reason, /revoked/);
});

test('A6 bad input throws before touching the network', async () => {
  await assert.rejects(() => verifyCharter({ uid: '0x1234', network: 'base', rpc: async () => '0x', ipfs: async () => new Uint8Array() }), /32 byte/);
  await assert.rejects(() => verifyCharter({ uid: UID, network: 'polygon', rpc: async () => '0x', ipfs: async () => new Uint8Array() }), /unknown network/);
});

test('A7 sha256Hex matches the known vector', async () => {
  assert.equal(await sha256Hex(new Uint8Array(Buffer.from('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('A9 the pointer-shaped result Base EAS really returns decodes too', () => {
  const inline = encodeAttestation({
    uid: UID, time: 1760000000, revocationTime: 0, recipient: '0x' + '00'.repeat(20),
    attester: ATTESTER, data: encodeCharterData(charter),
  });
  const pointerShape = '0x' + pad('20') + inline.slice(2);
  const a = decodeAttestation(pointerShape);
  assert.ok(a, 'pointer shape must decode');
  assert.equal(a.uid.toLowerCase(), UID);
  assert.equal(a.attester, ATTESTER);
  assert.equal(a.time, 1760000000);
  assert.equal(decodeCharterData(a.data).names.length, 3);
});

test('A8 parallel array mismatch in charter data is an error', () => {
  assert.throws(() => decodeCharterData(encodeCharterData({ ...charter, cids: charter.cids.slice(0, 2) })), /not parallel/);
});
