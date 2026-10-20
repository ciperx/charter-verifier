# charter-verifier

A static page that proves an on chain Founding Charter matches its published texts.

Paste an EAS attestation UID, pick Base or Base Sepolia, press Verify. The page reads the
attestation, fetches every text from IPFS, recomputes its sha256 and shows match or mismatch
per text. No backend, no key, no wallet.

## The page

Open `index.html` from any static host, or serve the folder:

```sh
python3 -m http.server 8080
```

Fields:

- Attestation UID, 32 bytes of hex.
- Network, Base (8453) or Base Sepolia (84532). This picks the chain and the public RPC,
  `https://mainnet.base.org` or `https://sepolia.base.org`.
- IPFS gateway, editable, default `https://ipfs.io/ipfs/`.

The attestation contract is the EAS predeploy at
`0x4200000000000000000000000000000000000021` on both networks.

## The module

`verifier.js` is an ES module with no dependency. It runs in the browser and in Node 20.

```js
import { verifyCharter, decodeCharterData, NETWORKS } from "./verifier.js";

const report = await verifyCharter({ uid, network: "base-sepolia", rpc, ipfs });
```

- `decodeCharterData(dataHex)` reads the attestation data, ABI encoded as
  `string version,string date,string[] names,bytes32[] digests,string[] cids`, and returns
  `{version, date, names, digests, cids}` with digests as `0x` and 64 lowercase hex.
- `verifyCharter({uid, network, rpc, ipfs})` returns
  `{ok, reason?, attestation: {uid, attester, time, revoked}, texts: [{name, cid, expected, actual, match, error?}]}`.
  `rpc(method, params)` sends one JSON-RPC call, `ipfs(cid)` returns the bytes of one text.
  `ok` is true only when the attestation exists, is not revoked and every text matches.
- `decodeAttestation(dataHex)` is exported too, as the struct reader behind the call.
- The module never throws for a missing attestation, a revoked one, a reverting RPC or a text
  it cannot fetch. Each case is a `reason` and, where it makes sense, an entry with `error`.

## Tests

```sh
npm test
```

Six tests, named after the acceptance item they prove:

- A1 `decodeCharterData` reads back what the schema encodes.
- A2 a matching attestation shows a match for each text and `ok` true.
- A3 a tampered text shows a mismatch for that text only, with both digests, and `ok` false.
- A4 an unknown UID, a revoked attestation, a reverting RPC and a text that cannot be fetched
  are reported plainly and never thrown.
- A5 both networks work, and the call goes to the EAS predeploy with the right selector and uid.
- A6 the page is mobile friendly at 360 px and a recorded Sepolia attestation verifies end to end.

`fixtures/charter.json` holds an ABI encoded EAS attestation with three texts, its digests and
the exact bytes behind each CID, made by `scripts/make-fixture.py`. The tests are offline: they
inject `rpc` and `ipfs`.

## The rehearsal UID

Kognai publishes a Sepolia rehearsal UID with the bundle. Paste it into the page with Base
Sepolia selected; the page reads it from the live chain and the live gateway. The recorded
fixture in this repository is a second, offline case, so the tests stay deterministic.

## House rules

Latin digits, no long dashes in any text people see, no secrets in the code or the logs.
