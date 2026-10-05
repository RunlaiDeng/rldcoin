"""Bounded fixture input from Native JSON; decoding grants no authorization.

Rust field order need not equal mesh-state key order. Native typed validation,
complete signatures, trust, finality and value execution remain mandatory.
"""
import json
import math
import stat
from pathlib import Path


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Native JSON field")
        result[key] = value
    return result


def _nonfinite(_text):
    raise ValueError("nonfinite Native JSON number")


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("nonfinite Native JSON number")
    return value


def decode_native_json(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique,
                      parse_constant=_nonfinite, parse_float=_float)


def read_native_json(path, limit=8 * 1024 * 1024):
    if type(limit) is not int or limit <= 0:
        raise ValueError("invalid Native JSON byte bound")
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError("unsafe or oversized Native JSON input")
    with path.open('rb') as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Native JSON grew beyond bound")
    return decode_native_json(raw)
