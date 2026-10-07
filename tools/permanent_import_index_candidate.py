"""Bounded append-only public import-ID commitment candidate, never ledger state.

An independently authenticated current root/scope is mandatory for proof use.
Membership/absence and an append-only root transition grant no import, credit,
finality, refund, custody or rollback authority. Existing Native limits stay put.
"""
from dataclasses import dataclass
import hashlib
import struct

DOMAIN = b'RLD-PERMANENT-IMPORT-INDEX-CANDIDATE-V1\0'
PROOF_DOMAIN = b'RLD-PERMANENT-IMPORT-PROOF-CANDIDATE-V1\0'
MAX_KEYS = 200001
MAX_DEPTH = 256
MAX_PROOF_BYTES = 32768
FRAME = struct.Struct('>32sHI64s')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def fixed(value, width):
    require(type(value) is bytes and len(value) == width, 'fixed public byte width differs')
    return value


def prefix(key, bit):
    require(type(bit) is int and 0 <= bit <= 255, 'branch bit outside bound')
    return (int.from_bytes(key, 'big') >> (256 - bit) << (256 - bit)).to_bytes(32, 'big')


def side(key, bit):
    return key[bit // 8] >> (7 - bit % 8) & 1


def empty_hash(scope):
    return hashlib.sha512(DOMAIN + fixed(scope, 64) + b'E').digest()


def leaf_hash(scope, key):
    return hashlib.sha512(DOMAIN + fixed(scope, 64) + b'L' + fixed(key, 32)).digest()


def branch_hash(scope, bit, common, left_hash, left_count, right_hash, right_count):
    fixed(scope, 64)
    fixed(common, 32)
    require(prefix(common, bit) == common, 'noncanonical compressed prefix')
    require(type(left_count) is int and type(right_count) is int
            and 1 <= left_count and 1 <= right_count
            and left_count + right_count <= MAX_KEYS, 'committed count outside bound')
    return hashlib.sha512(DOMAIN + scope + b'B' + common + bit.to_bytes(2, 'big')
                          + left_count.to_bytes(4, 'big') + fixed(left_hash, 64)
                          + right_count.to_bytes(4, 'big') + fixed(right_hash, 64)).digest()


@dataclass(frozen=True, slots=True)
class Node:
    key: bytes  # A retained representative; every descendant has branch prefix.
    bit: int
    left: object
    right: object
    digest: bytes
    count: int


@dataclass(frozen=True, slots=True)
class ProofFrame:
    common: bytes
    bit: int
    sibling_count: int
    sibling_hash: bytes


@dataclass(frozen=True, slots=True)
class Proof:
    terminal_key: bytes | None
    frames: tuple


def node_leaf(scope, key):
    return Node(key, 256, None, None, leaf_hash(scope, key), 1)


def node_branch(scope, bit, left, right):
    require(left.bit > bit and right.bit > bit
            and side(left.key, bit) == 0 and side(right.key, bit) == 1
            and prefix(left.key, bit) == prefix(right.key, bit), 'branch shape differs')
    common = prefix(left.key, bit)
    digest = branch_hash(scope, bit, common, left.digest, left.count, right.digest, right.count)
    return Node(left.key, bit, left, right, digest, left.count + right.count)


def fork(scope, old, new):
    difference = int.from_bytes(old.key, 'big') ^ int.from_bytes(new.key, 'big')
    require(difference != 0, 'permanent import ID already present')
    bit = 256 - difference.bit_length()
    return node_branch(scope, bit, old, new) if side(new.key, bit) else node_branch(scope, bit, new, old)


class Index:
    """RAM-only candidate construction; no delete, serialized authority or trust."""
    def __init__(self, scope):
        self.scope = fixed(scope, 64)
        self._node = None

    @property
    def root(self):
        return self._node.digest if self._node else empty_hash(self.scope)

    @property
    def count(self):
        return self._node.count if self._node else 0

    def proof(self, key):
        fixed(key, 32)
        node, frames = self._node, []
        while node is not None and node.bit != 256:
            chosen = side(key, node.bit)
            sibling = node.left if chosen else node.right
            frames.append(ProofFrame(prefix(node.key, node.bit), node.bit, sibling.count, sibling.digest))
            node = node.right if chosen else node.left
        return Proof(node.key if node else None, tuple(frames))

    def insert(self, key):
        fixed(key, 32)
        require(self.count < MAX_KEYS, 'candidate permanent-key capacity exhausted')
        incoming = node_leaf(self.scope, key)

        def add(node):
            if node is None:
                return incoming
            difference = int.from_bytes(node.key, 'big') ^ int.from_bytes(key, 'big')
            require(difference != 0, 'permanent import ID already present')
            split = 256 - difference.bit_length()
            if split < node.bit:
                return fork(self.scope, node, incoming)
            if side(key, node.bit):
                return node_branch(self.scope, node.bit, node.left, add(node.right))
            return node_branch(self.scope, node.bit, add(node.left), node.right)

        # Publish only the fully formed immutable new tree; all refusals leave it intact.
        self._node = add(self._node)
        return self.root


def proof_root(scope, query, proof):
    fixed(scope, 64)
    fixed(query, 32)
    require(type(proof) is Proof and type(proof.frames) is tuple
            and len(proof.frames) <= MAX_DEPTH, 'proof type/depth differs')
    if proof.terminal_key is None:
        require(not proof.frames, 'empty proof has branch frames')
        return empty_hash(scope), 0, False
    terminal = fixed(proof.terminal_key, 32)
    previous = -1
    for frame in proof.frames:
        require(type(frame) is ProofFrame and type(frame.bit) is int
                and previous < frame.bit <= 255, 'nonordered proof branch')
        require(fixed(frame.common, 32) == prefix(terminal, frame.bit)
                and side(terminal, frame.bit) == side(query, frame.bit), 'wrong branch route/prefix')
        previous = frame.bit
    digest, count = leaf_hash(scope, terminal), 1
    for frame in reversed(proof.frames):
        if side(query, frame.bit):
            digest = branch_hash(scope, frame.bit, frame.common, frame.sibling_hash,
                                 frame.sibling_count, digest, count)
        else:
            digest = branch_hash(scope, frame.bit, frame.common, digest, count,
                                 frame.sibling_hash, frame.sibling_count)
        count += frame.sibling_count
    return digest, count, terminal == query


def verify_key_proof(scope, independently_expected_root, query, proof):
    fixed(independently_expected_root, 64)
    root, _, present = proof_root(scope, query, proof)
    require(root == independently_expected_root, 'proof differs from independently retained root')
    return present


def derive_insert_root(scope, independently_expected_root, query, proof):
    """Pure one-key append proof; no state installation, import or nonce use."""
    fixed(independently_expected_root, 64)
    old_root, count, present = proof_root(scope, query, proof)
    require(old_root == independently_expected_root and not present and count < MAX_KEYS,
            'wrong root, duplicate ID or candidate key capacity')
    if proof.terminal_key is None:
        return leaf_hash(scope, query)
    old_key = proof.terminal_key
    split = 256 - (int.from_bytes(old_key, 'big') ^ int.from_bytes(query, 'big')).bit_length()
    digest, count, inserted = leaf_hash(scope, old_key), 1, False

    def wrap(digest, count):
        incoming = leaf_hash(scope, query)
        common = prefix(query, split)
        if side(query, split):
            return branch_hash(scope, split, common, digest, count, incoming, 1)
        return branch_hash(scope, split, common, incoming, 1, digest, count)

    for frame in reversed(proof.frames):
        if not inserted and frame.bit < split:
            digest = wrap(digest, count)
            count += 1
            inserted = True
        if side(query, frame.bit):
            digest = branch_hash(scope, frame.bit, frame.common, frame.sibling_hash,
                                 frame.sibling_count, digest, count)
        else:
            digest = branch_hash(scope, frame.bit, frame.common, digest, count,
                                 frame.sibling_hash, frame.sibling_count)
        count += frame.sibling_count
    return digest if inserted else wrap(digest, count)


def encode_proof(proof):
    require(type(proof) is Proof and type(proof.frames) is tuple
            and len(proof.frames) <= MAX_DEPTH, 'proof shape differs')
    raw = PROOF_DOMAIN + bytes([proof.terminal_key is not None])
    if proof.terminal_key is not None:
        raw += fixed(proof.terminal_key, 32)
    else:
        require(not proof.frames, 'empty proof cannot carry branches')
    raw += len(proof.frames).to_bytes(2, 'big')
    for frame in proof.frames:
        require(type(frame) is ProofFrame and type(frame.bit) is int and type(frame.sibling_count) is int
                and 0 <= frame.bit <= 255 and 1 <= frame.sibling_count < MAX_KEYS,
                'proof frame outside bounds')
        raw += FRAME.pack(fixed(frame.common, 32), frame.bit, frame.sibling_count,
                          fixed(frame.sibling_hash, 64))
    require(len(raw) <= MAX_PROOF_BYTES, 'proof byte bound exceeded')
    return raw


def decode_proof(raw):
    require(type(raw) is bytes and len(raw) <= MAX_PROOF_BYTES
            and raw.startswith(PROOF_DOMAIN), 'proof encoding/byte bound differs')
    offset = len(PROOF_DOMAIN)
    require(len(raw) >= offset + 3 and raw[offset] in (0, 1), 'proof header differs')
    kind = raw[offset]
    offset += 1
    terminal = raw[offset:offset + 32] if kind else None
    offset += 32 if kind else 0
    require(len(raw) >= offset + 2, 'proof count missing')
    count = int.from_bytes(raw[offset:offset + 2], 'big')
    offset += 2
    require(count <= MAX_DEPTH and len(raw) == offset + count * FRAME.size, 'proof length/count differs')
    frames = tuple(ProofFrame(*FRAME.unpack_from(raw, offset + i * FRAME.size)) for i in range(count))
    proof = Proof(terminal, frames)
    require(encode_proof(proof) == raw, 'noncanonical proof refused')
    return proof
