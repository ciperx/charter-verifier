# charter-verifier

Prove that the Founding Charter attested on chain matches its published texts.

Give it an [EAS](https://attest.sh) attestation UID on **Base** (8453) or **Base Sepolia** (84532).
It reads the attestation from the EAS contract at `0x4200000000000000000000000000000000000021`,
fetches every text from IPFS, recomputes its sha256 and shows **match or mismatch per text**.

Schema of the attestation data:

```
string version,string date,string[] names,bytes32[] digests,string[] cids
```

`names`, `digests` and `cids` are parallel arrays; each digest is the sha256 of the exact bytes
stored under its CID.

## Interface

Static HTML + CSS + JS. **No backend, no build step, no dependencies.**

- `index.html` — the page (open it directly, or serve the folder).
- `verifier.js` — ES module with the logic; runs in the browser **and** in Node 20+.

Exports:

```js
decodeCharterData(dataHex) // -> {version, date, names, digests, cids}
decodeAttestation(resultHex) // -> Attestation | null  (handles Base's pointer-shaped result)
encodeGetAttestation(uid) // -> eth_call data with selector 0xa3112a64
verifyCharter({uid, network, rpc, ipfs}) // -> {ok, reason?, attestation, texts}
sha256Hex(bytes) // -> hex digest
jsonRpc(url) / ipfsGateway(url) / PUBLIC_RPC // ready-made fetch based transports
```

`verifyCharter` never throws for a missing attestation, a revoked one, or a text it cannot fetch —
it reports them. `ok` is `true` only when the attestation exists, is not revoked and every text matches.

Addresses and the digest are compared lowercase; nothing here needs a key or a wallet connection.

## Use it in Node

```js
import { verifyCharter, jsonRpc, ipfsGateway, PUBLIC_RPC } from './verifier.js';

const report = await verifyCharter({
  uid: '0x…',                       // 32 byte attestation uid
  network: 'base',                  // or 'base-sepolia'
  rpc: jsonRpc(PUBLIC_RPC.base),    // any JSON-RPC endpoint
  ipfs: ipfsGateway('https://ipfs.io/ipfs/'),
});

console.log(report.ok, report.reason ?? '', report.texts);
```

## Tests

```bash
node --test test/verifier.test.mjs
```

12 tests, no network: a synthetic ABI encoder builds charter data and an EAS answer, then
`verifyCharter` is driven through a fake `rpc` and a fake `ipfs` — matching attestation, one
tampered text, one unreachable text, missing attestation, revoked attestation, invalid input,
and the pointer-shaped result Base actually returns (checked against
`eth_call` on `https://mainnet.base.org`).

## Notes from the live chain

- `getAttestation(bytes32)` selector is `0xa3112a64`.
- Base's EAS answers with the struct behind a leading offset word (`0x20…`); both that and the
  inline ABI shape decode.
- A UID with no attestation returns a zeroed struct — reported as `no attestation with that uid`.

MIT.
