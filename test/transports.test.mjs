// A5: the network chooses the chain and the RPC. A6: the page is mobile friendly.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { PUBLIC_RPC, EAS_CHAIN, jsonRpc, verifyCharter } from '../verifier.js';

test('A5 base and base-sepolia use their own chain id and RPC host', async () => {
  assert.equal(EAS_CHAIN.base, 8453);
  assert.equal(EAS_CHAIN['base-sepolia'], 84532);
  assert.match(PUBLIC_RPC.base, /mainnet\.base\.org/);
  assert.match(PUBLIC_RPC['base-sepolia'], /sepolia\.base\.org/);

  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.push(String(url));
    const body = JSON.parse(String(init.body));
    assert.equal(body.method, 'eth_call');
    // a missing attestation is a valid, reportable answer
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: '0x' }), {
      status: 200, headers: { 'content-type': 'application/json' },
    });
  };
  try {
    const uid = '0x' + '11'.repeat(32);
    const a = await verifyCharter({ uid, network: 'base', rpc: jsonRpc(PUBLIC_RPC.base), ipfs: async () => new Uint8Array() });
    const b = await verifyCharter({ uid, network: 'base-sepolia', rpc: jsonRpc(PUBLIC_RPC['base-sepolia']), ipfs: async () => new Uint8Array() });
    assert.equal(a.ok, false);
    assert.equal(b.ok, false);
    assert.equal(seen.length, 2);
    assert.match(seen[0], /mainnet\.base\.org/);
    assert.match(seen[1], /sepolia\.base\.org/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('A6 the page is mobile friendly and loads the verifier as an ES module', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(html, /<meta[^>]+name="viewport"[^>]+width=device-width/);
  assert.match(html, /type="module"/);
  assert.match(html, /verifier\.js/);
  // no secrets in the page
  assert.doesNotMatch(html, /privateKey|mnemonic|api[_-]?key/i);
});
