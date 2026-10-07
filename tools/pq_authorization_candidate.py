"""Verification-only hybrid authorization candidate, outside every adopted profile.

The caller must supply an independently authenticated policy and observation
position. A VERIFIED result means both signatures match that candidate policy;
it cannot authorize admission, signing, money, an epoch change or ledger import.
Private keys and signing are deliberately absent from this interface.
"""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import json
import os
import re
import stat
import subprocess
import time

PROFILE = "RLDCOIN-HYBRID-AUTH-CANDIDATE-V1"
MESSAGE_DOMAIN = PROFILE.encode("ascii") + b"\0"
PQ_CONTEXT = "RLDCOIN-PQ-AUTH-CANDIDATE-V1"
PURPOSES = frozenset({"PAYMENT", "FINALITY", "ADMISSION", "GOVERNANCE", "RENEWAL", "ARCHIVE_MANIFEST"})
ED_SPKI = bytes.fromhex("302a300506032b6570032100")
PQ_SPKI = bytes.fromhex("30820a32300b060960864801650304031303820a2100")
U64_MAX = (1 << 64) - 1
MAX_INTENT_BYTES = 2048


class Rejected(ValueError):
    pass


class Result(Enum):
    VERIFIED = "candidate_signatures_verified"
    REJECTED = "candidate_signatures_rejected"
    UNAVAILABLE = "candidate_verification_unavailable"


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def uint(value, minimum=1):
    require(type(value) is int and minimum <= value <= U64_MAX, "invalid integer position")


def digest(value, width):
    require(type(value) is str and len(value) == width and re.fullmatch("[0-9a-f]+", value),
            "invalid canonical root")


# Public-point admission only; not a secret-key or signature implementation.
# Edwards arithmetic/encoding: RFC8032 sections5.1.3/6, with this candidate's
# explicit nonidentity prime-subgroup restriction matching Core admission.
ED_FIELD = (1 << 255) - 19
ED_ORDER = (1 << 252) + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_FIELD - 2, ED_FIELD) % ED_FIELD
ED_SQRT_MINUS_ONE = pow(2, (ED_FIELD - 1) // 4, ED_FIELD)


def prime_order_ed_point(encoded):
    if type(encoded) is not bytes or len(encoded) != 32:
        return False
    n = int.from_bytes(encoded, 'little')
    y, sign = n & ((1 << 255) - 1), n >> 255
    if y >= ED_FIELD:
        return False
    yy = y * y % ED_FIELD
    denominator = (ED_D * yy + 1) % ED_FIELD
    if denominator == 0:
        return False
    xx = (yy - 1) * pow(denominator, ED_FIELD - 2, ED_FIELD) % ED_FIELD
    x = pow(xx, (ED_FIELD + 3) // 8, ED_FIELD)
    if x * x % ED_FIELD != xx:
        x = x * ED_SQRT_MINUS_ONE % ED_FIELD
    if x * x % ED_FIELD != xx or (x == 0 and sign):
        return False
    if x & 1 != sign:
        x = (-x) % ED_FIELD
    if x == 0 and y == 1:
        return False

    def add(left, right):
        lx, ly, lz, lt = left
        rx, ry, rz, rt = right
        a = (ly - lx) * (ry - rx) % ED_FIELD
        b = (ly + lx) * (ry + rx) % ED_FIELD
        c = 2 * ED_D * lt * rt % ED_FIELD
        d = 2 * lz * rz % ED_FIELD
        e, f, g, h = b - a, d - c, d + c, b + a
        return tuple(v % ED_FIELD for v in (e * f, g * h, f * g, e * h))

    point = (x, y, 1, x * y % ED_FIELD)
    result = (0, 1, 1, 0)
    scalar = ED_ORDER
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    px, py, pz, _ = result
    return pz != 0 and px == 0 and py == pz


@dataclass(frozen=True)
class Policy:
    profile: str
    currency_root: str
    region_root: str
    purpose: str
    valid_from_epoch: int
    valid_until_epoch: int
    ed_public_der: bytes
    pq_public_der: bytes

    def validate(self):
        require(self.profile == PROFILE, "unimplemented candidate profile")
        digest(self.currency_root, 64)
        digest(self.region_root, 64)
        require(self.purpose in PURPOSES, "unknown candidate purpose")
        uint(self.valid_from_epoch)
        uint(self.valid_until_epoch)
        require(self.valid_from_epoch <= self.valid_until_epoch, "invalid finite epoch horizon")
        require(type(self.ed_public_der) is bytes and len(self.ed_public_der) == 44
                and self.ed_public_der.startswith(ED_SPKI), "wrong classical key encoding")
        require(prime_order_ed_point(self.ed_public_der[len(ED_SPKI):]),
                "classical key needs canonical nonidentity prime-order point")
        require(type(self.pq_public_der) is bytes and len(self.pq_public_der) == 2614
                and self.pq_public_der.startswith(PQ_SPKI), "wrong ML-DSA-87 key encoding")


@dataclass(frozen=True)
class Proof:
    ed_signature: bytes
    pq_signature: bytes


def signing_bytes(intent):
    require(type(intent) is dict and set(intent) == {
        "candidate_only", "currency_root", "region_root", "purpose", "epoch", "nonce", "payload_root"
    }, "candidate intent fields differ")
    require(intent["candidate_only"] is True, "not a no-value candidate intent")
    digest(intent["currency_root"], 64)
    digest(intent["region_root"], 64)
    digest(intent["payload_root"], 128)
    require(type(intent["purpose"]) is str and intent["purpose"] in PURPOSES, "unknown purpose")
    uint(intent["epoch"])
    uint(intent["nonce"])
    encoded = json.dumps(intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    require(len(encoded) <= MAX_INTENT_BYTES, "candidate intent exceeds bound")
    return MESSAGE_DOMAIN + encoded


def decode_intent(raw):
    require(type(raw) is bytes and len(raw) <= MAX_INTENT_BYTES, "candidate input exceeds bound")
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate candidate field")
            result[key] = value
        return result
    def non_integer(_):
        raise Rejected("non-integer candidate encoding")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=non_integer, parse_constant=non_integer)
    except (ValueError, RecursionError) as error:
        raise Rejected("invalid candidate JSON") from error
    signing_bytes(value)
    return value


def verify_candidate(policy, intent, proof, trusted_epoch, scratch, openssl, deadline):
    """Both signatures, exact caller-pinned roots/role and finite horizon are required.

    scratch must be a fresh directory. Only bounded public verification bytes
    are written; they are retained. No key lookup, alternate algorithm, signing,
    receipt issuance, clock inference or authorization fallback occurs here.
    """
    try:
        require(type(policy) is Policy and type(proof) is Proof, "candidate types differ")
        policy.validate()
        message = signing_bytes(intent)
        uint(trusted_epoch)
        require(policy.valid_from_epoch <= trusted_epoch <= policy.valid_until_epoch,
                "observation outside finite verification horizon")
        require(policy.valid_from_epoch <= intent["epoch"] <= trusted_epoch,
                "intent outside trusted epoch scope")
        require(intent["currency_root"] == policy.currency_root
                and intent["region_root"] == policy.region_root
                and intent["purpose"] == policy.purpose, "intent outside pinned authority scope")
        require(type(proof.ed_signature) is bytes and len(proof.ed_signature) == 64
                and type(proof.pq_signature) is bytes and len(proof.pq_signature) == 4627,
                "both complete signature halves are mandatory")
        require(prime_order_ed_point(proof.ed_signature[:32])
                and int.from_bytes(proof.ed_signature[32:], "little") < ED_ORDER,
                "classical signature needs canonical prime-order R and scalar")
    except (Rejected, TypeError):
        return Result.REJECTED
    try:
        scratch = Path(scratch)
        parent = scratch.parent.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid(), "unowned scratch parent")
        scratch.mkdir(mode=0o700)
        values = {"intent.bin": message, "ed-public.der": policy.ed_public_der,
                  "pq-public.der": policy.pq_public_der, "ed-signature.bin": proof.ed_signature,
                  "pq-signature.bin": proof.pq_signature}
        for name, data in values.items():
            with (scratch / name).open("xb") as output:
                output.write(data)
        env = dict(os.environ, OPENSSL_CONF="/dev/null")
        env.pop("OPENSSL_MODULES", None)
        outcomes = []
        for label in ("ed", "pq"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return Result.UNAVAILABLE
            context = ["-pkeyopt", "context-string:" + PQ_CONTEXT] if label == "pq" else []
            result = subprocess.run([str(openssl), "pkeyutl", "-verify", "-rawin", "-pubin",
                                     "-keyform", "DER", "-inkey", str(scratch / (label + "-public.der")),
                                     "-in", str(scratch / "intent.bin"), "-sigfile",
                                     str(scratch / (label + "-signature.bin")), "-provider", "default", *context],
                                    cwd=Path(__file__).resolve().parents[1], env=env,
                                    capture_output=True, timeout=min(5, remaining))
            if result.returncode == 0:
                outcomes.append(True)
            elif result.returncode == 1 and b"Signature Verification Failure" in result.stdout:
                outcomes.append(False)
            else:
                return Result.UNAVAILABLE
        # An OR here would preserve the weak old authorization path.
        return Result.VERIFIED if all(outcomes) else Result.REJECTED
    except (OSError, subprocess.SubprocessError, Rejected):
        return Result.UNAVAILABLE
