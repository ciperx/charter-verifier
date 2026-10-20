"""Build a realistic EAS attestation fixture (ABI encoded) for the charter verifier tests."""
import base64
import hashlib
import json
import os

from eth_abi import encode
from eth_utils import keccak

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
os.makedirs(ROOT, exist_ok=True)

TEXTS = [
    ("charter", "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy", "# Founding Charter\n\nA protocol is a promise made concrete.\n"),
    ("constitution", "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy", "## Constitution\n\n1. No secrets in the open.\n2. Every claim is checkable.\n"),
    ("soul", "bafkreid7qoywk77r7rj6rj6rj6rj6rj6rj6rj6rj6rj6rj6rj6rj6rj", "Soul: plain words, no dash, Latin digits only.\n"),
]

NAMES = [name for name, _cid, _text in TEXTS]
CIDS = [cid for _name, cid, _text in TEXTS]
DIGESTS = [bytes.fromhex(hashlib.sha256(text.encode()).hexdigest()) for _n, _c, text in TEXTS]

VERSION = "1.0.0"
DATE = "2026-10-20"

charter_data = encode(
    ["string", "string", "string[]", "bytes32[]", "string[]"],
    [VERSION, DATE, NAMES, DIGESTS, CIDS],
)

UID = keccak(text="charter-fixture-one")
SCHEMA = keccak(text="string version,string date,string[] names,bytes32[] digests,string[] cids")
ZERO = b"\x00" * 32
ATTESTER = "0x" + "11" * 20
RECIPIENT = "0x" + "22" * 20


def attestation_blob(revocation_time=0):
    return "0x" + encode(
        ["bytes32", "bytes32", "uint64", "uint64", "uint64", "bytes32", "address", "address", "bool", "bytes"],
        [UID, SCHEMA, 1761000000, 0, revocation_time, ZERO, RECIPIENT, ATTESTER, True, charter_data],
    ).hex()


fixture = {
    "uid": "0x" + UID.hex(),
    "network": "base-sepolia",
    "attestation": attestation_blob(),
    "revoked_attestation": attestation_blob(revocation_time=1762000000),
    "texts": [
        {"name": name, "cid": cid, "content_base64": base64.b64encode(text.encode()).decode()}
        for name, cid, text in TEXTS
    ],
    "expected_digests": ["0x" + digest.hex() for digest in DIGESTS],
    "version": VERSION,
    "date": DATE,
}

with open(os.path.join(ROOT, "charter.json"), "w") as handle:
    json.dump(fixture, handle, indent=1)
    handle.write("\n")

print("fixture written", os.path.getsize(os.path.join(ROOT, "charter.json")), "bytes")
print("uid", fixture["uid"])
