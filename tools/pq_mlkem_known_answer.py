#!/usr/bin/env python3
"""One pinned NIST ML-KEM-768 case on two separately selected engines; no adoption."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

CORPORA = {
    'decap': ('998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91', '9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf', 5, 86),
    'encap': ('998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91', '9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf', 2, 26),
    'keygen': ('3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523', 'a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4', 2, 26),
}
PROJECT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def corpus(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1048576:
            raise ValueError('bounded regular corpus required')
        raw = file.read(1048577)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('fixed official corpus digest differs')
    return json.loads(raw)


def select(doc, group, case):
    groups = [g for g in doc['testGroups'] if g['tgId'] == group]
    if len(groups) != 1:
        raise ValueError('official group unavailable')
    tests = [t for t in groups[0]['tests'] if t['tcId'] == case]
    if len(tests) != 1:
        raise ValueError('official case unavailable')
    return groups[0], tests[0]


def material(mode, prompt, expected):
    if mode == 'decap':
        return [('dk', prompt['dk'], 2400), ('c', prompt['c'], 1088), ('k', expected['k'], 32)]
    if mode == 'encap':
        return [('ek', prompt['ek'], 1184), ('m', prompt['m'], 32), ('c', expected['c'], 1088), ('k', expected['k'], 32)]
    return [('d', prompt['d'], 32), ('z', prompt['z'], 32), ('ek', expected['ek'], 1184), ('dk', expected['dk'], 2400)]


def run(args):
    started = time.monotonic()
    deadline = started + 120
    hashes = CORPORA[args.mode]
    p = corpus(args.prompt, hashes[0])
    e = corpus(args.expected, hashes[1])
    case = hashes[3] if args.case is None else args.case
    group, pt = select(p, hashes[2], case)
    _, et = select(e, hashes[2], case)
    if group['parameterSet'] != 'ML-KEM-768':
        raise ValueError('wrong parameter set')
    engines = [(args.c_binary.resolve(strict=True), args.c_sha256), (args.rust_binary.resolve(strict=True), args.rust_sha256)]
    for path, expected_hash in engines:
        if not stat.S_ISREG(path.stat().st_mode) or digest(path) != expected_hash:
            raise ValueError('selected actual binary digest differs')
    if engines[0][0] == engines[1][0] or engines[0][1] == engines[1][1]:
        raise ValueError('two different actual engine binaries required')
    parent = args.output.parent.resolve(strict=True)
    info = parent.stat()
    if parent == PROJECT or parent.is_relative_to(PROJECT):
        raise ValueError('output must be outside public project tree')
    if info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode):
        raise ValueError('owned output parent required')
    output = parent / args.output.name
    output.mkdir(mode=0o700)  # Fresh only; never reuse failed input/output directories.
    report = dict(candidate_only=True, installed=False, mode=args.mode, group=hashes[2], case=case,
                  controller_sha256=digest(Path(__file__)), corpus_sha256=hashes[:2],
                  engine_sha256=[x[1] for x in engines], budget_seconds=120, observations=[], completed=False)
    originals = {}
    try:
        paths = []
        for name, encoded, size in material(args.mode, pt, et):
            raw = bytes.fromhex(encoded)
            if len(raw) != size:
                raise ValueError('official vector has wrong size')
            path = output / name
            with path.open('xb') as file:
                os.chmod(path, 0o600)
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            originals[path] = digest(path)
            paths.append(path)
        wrong = output / 'wrong-expected'
        raw = bytearray(paths[-1].read_bytes())
        raw[0] ^= 1
        with wrong.open('xb') as file:
            os.chmod(wrong, 0o600)
            file.write(raw)
            file.flush()
            os.fsync(file.fileno())
        originals[wrong] = digest(wrong)
        env = dict(os.environ, OPENSSL_CONF='/dev/null')
        env.pop('OPENSSL_MODULES', None)
        for engine, expected_hash in engines:
            for negative in (False, True):
                inputs = paths[:-1] + [wrong] if negative else paths
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('original120 deadline exhausted')
                result = subprocess.run([str(engine), *map(str, inputs)], cwd=PROJECT, env=env,
                                        capture_output=True, timeout=remaining, check=False)
                report['observations'].append(dict(binary_sha256=expected_hash, negative=negative,
                                                   returncode=result.returncode))
                # Comparator inputs/output have no runtime or custody authority.
                if result.returncode != (1 if negative else 0):
                    raise ValueError('actual comparator outcome differs from case predicate')
                if digest(engine) != expected_hash:
                    raise ValueError('actual binary changed during scope')
        if any(digest(path) != expected for path, expected in originals.items()):
            raise ValueError('retained input bytes changed')
        if corpus(args.prompt, hashes[0]) != p or corpus(args.expected, hashes[1]) != e:
            raise ValueError('official source changed during scope')
        if time.monotonic() >= deadline:
            raise TimeoutError('original120 whole-scope deadline exhausted')
        report['completed'] = True
    except Exception as error:
        report['failure'] = f'{type(error).__name__}: {error}'
    report['duration_seconds'] = time.monotonic() - started
    report['retained_input_sha256'] = {p.name: expected for p, expected in originals.items()}
    target = output / 'outcome.json'
    with target.open('x') as file:
        os.chmod(target, 0o600)
        json.dump(report, file, indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())
    print(json.dumps(dict(completed=report['completed'], outcome=str(target), duration_seconds=report['duration_seconds'])))
    return 0 if report['completed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=CORPORA, required=True)
    parser.add_argument('--case', type=int, help='one tcId in the fixed official ML-KEM-768 group')
    for name in ('prompt', 'expected', 'c-binary', 'rust-binary', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('c-sha256', 'rust-sha256'):
        parser.add_argument('--' + name, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
