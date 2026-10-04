"""Independent integer reference for the frozen section-6 issuance component.

Arithmetic vectors only: never a ledger, signing, freshness or adoption input.
"""
import argparse
import hashlib
import json
from pathlib import Path

CAP = 10**35
ERA = 200000
MAX_HEIGHT = 2**128 - 1
FORMAT = 'RLD-EARTH-POW-RESERVE-ERA-V1-VECTORS'


def bounded(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('bounded unsigned integer required')
    return value


def budget(reserve):
    bounded(reserve, CAP)
    return reserve if reserve < 2 else reserve // 2


def reserve_at_era(era):
    bounded(era, MAX_HEIGHT)
    reserve = CAP
    # Halving terminates after the single-unit era; no height-sized iteration.
    while era and reserve:
        reserve -= budget(reserve)
        era -= 1
    return reserve


def cumulative(blocks):
    bounded(blocks, MAX_HEIGHT)
    eras, selected_slots = divmod(blocks, ERA)
    reserve = reserve_at_era(eras)
    quotient, remainder = divmod(budget(reserve), ERA)
    return CAP - reserve + quotient * selected_slots + min(selected_slots, remainder)


def reward(height):
    bounded(height, MAX_HEIGHT)
    if height == 0:
        raise ValueError('genesis issues no reward')
    era, slot = divmod(height - 1, ERA)
    quotient, remainder = divmod(budget(reserve_at_era(era)), ERA)
    return quotient + int(slot < remainder)


def component_hash(root):
    return hashlib.sha256(b'RLD-ISSUANCE-RESERVE-ERA-V1\0' +
        (root/'docs/spec/RESERVE-ERA-ISSUANCE-V1.md').read_bytes()).hexdigest()


def decimal(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit() or str(int(value)) != value:
        raise ValueError('canonical unsigned decimal required')
    return bounded(int(value), MAX_HEIGHT)


def verify(path, root):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('bounded vector file required')
    data = json.loads(path.read_text())
    if data.get('format') != FORMAT or data.get('issuance_rules_sha256') != component_hash(root):
        raise ValueError('explicit new issuance vector format/component required')
    if (data.get('reference_implementation_sha256') != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            or data.get('legacy_parent_vector_sha256') != hashlib.sha256(
                (root/'vectors/earth-pow/vectors.json').read_bytes()).hexdigest()):
        raise ValueError('exact reference and retained legacy vector binding required')
    rows = data['emission']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 512:
        raise ValueError('bounded complete emission vectors required')
    for row in rows:
        height = decimal(row['blocks'])
        if cumulative(height) != decimal(row['cumulative_runlai']):
            raise ValueError('cumulative vector differs')
        expected_reward = 0 if height == 0 else reward(height)
        if expected_reward != decimal(row['reward_runlai']):
            raise ValueError('reward vector differs')
    return len(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(dict(checked=verify(args.check, args.root), native_authority=False)))
