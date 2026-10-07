from pathlib import Path
import json, hashlib, time, subprocess, os, datetime
r = Path.cwd()
assert r == Path('/Users/galaxy/GitHub/rldcoin')
b, e = r / 'tmp/default-relay-20260930', r / 'docs/operations/evidence'
name = 'pq-quorum-reverse-provider-v7-20261007'
root, stagep, out = b / (name + '-public'), e / (name + '-stage.json'), e / (name + '-checks.json')
assert not any(p.exists() for p in (root, stagep, out))
previousp = e / 'pq-quorum-carriage-v6-20261007-checks.json'
q = json.loads(previousp.read_bytes())
assert q['completed'] and q['cumulative_seconds'] == 34.351839
old = b / 'pq-quorum-carriage-v6-20261007-private'
public_roster, public_quorum = old / 'caller-trusted-public-roster.json', old / 'genuine-public-quorum.json'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
openssl = Path('/opt/homebrew/opt/openssl@3/bin/openssl')
inventory = json.loads((old / 'PRIVATE_INVENTORY.json').read_bytes())
entries = {v['path']: v for v in inventory['files']}
for p in (public_roster, public_quorum):
    assert sha(p) == entries[p.name]['sha256']
protected = {str(p): sha(p) for p in (Path(__file__), previousp, old / 'PRIVATE_INVENTORY.json', public_roster,
    public_quorum, openssl, Path('/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib'))}
def pins():
    assert all(sha(Path(p)) == h for p, h in protected.items())
stage = dict(format='RLD-PQ-QUORUM-REVERSE-PROVIDER-V7', budget_seconds=120, attempts=1,
    previous_used_seconds=q['cumulative_seconds'], protected_sha256=protected,
    hypothesis='Verify all three fresh fips204/dalek public quorum signatures in independent OpenSSL3.6.3 default implementation, '
        'rather than only self-library verification or prior OpenSSL-to-Rust direction. Read exact two public files from successful V6, '
        'never retained private keys. Verify six actual halves and refuse changed Ed/PQ/wrongcontext with no signing/network/Node/Native/Runtime. '
        'Continue remaining original120 including public extraction and sealing; old V5 FAIL and V6 source-bound pass preserved.',
    exit='First guard/outcome/provider error or original120 refuses and preserves failure; no unchanged retry or authorization grant.',
    core_source=q['core_source'], production_source_changes=0, signing_calls=0, network_calls=0, whole_goal_completed=False)
pins()
stagep.write_text(json.dumps(stage, indent=2) + '\n')
start = time.monotonic()
deadline = start + (120 - q['cumulative_seconds'])
root.mkdir(mode=0o700)
results, error = [], None
env = dict(os.environ, OPENSSL_CONF='/dev/null')
env.pop('OPENSSL_MODULES', None)
try:
    roster = json.loads(public_roster.read_bytes())
    quorum = json.loads(public_quorum.read_bytes())
    for member in quorum['members']:
        index = member['member']
        envelope = member['envelope']
        policy = roster['members'][index]
        message = b'RLDCOIN-HYBRID-AUTH-CANDIDATE-V1\0' + json.dumps(envelope['intent'], sort_keys=True, separators=(',', ':')).encode()
        msgp = root / ('member' + str(index) + '-message.bin')
        msgp.write_bytes(message)
        protected[str(msgp)] = sha(msgp)
        for label, prefix in [('ed', '302a300506032b6570032100'), ('pq', '30820a32300b060960864801650304031303820a2100')]:
            key = root / ('member' + str(index) + '-' + label + '-public.der')
            signature = root / ('member' + str(index) + '-' + label + '-signature.bin')
            key.write_bytes(bytes.fromhex(prefix + policy[label + '_public_key']))
            signature.write_bytes(bytes.fromhex(envelope[label + '_signature']))
            protected[str(key)] = sha(key)
            protected[str(signature)] = sha(signature)
            for variant in ('genuine', 'changed-signature', 'wrong-context') if index == 0 and label == 'pq' else (('genuine', 'changed-signature') if index == 0 else ('genuine',)):
                tested = signature
                if variant == 'changed-signature':
                    tested = root / ('member' + str(index) + '-' + label + '-changed-signature.bin')
                    raw = signature.read_bytes()
                    tested.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                    protected[str(tested)] = sha(tested)
                context = 'wrong-context' if variant == 'wrong-context' else 'RLDCOIN-PQ-AUTH-CANDIDATE-V1'
                command = [str(openssl), 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER', '-inkey', str(key),
                    '-in', str(msgp), '-sigfile', str(tested), '-provider', 'default']
                if label == 'pq': command += ['-pkeyopt', 'context-string:' + context]
                pins()
                at = time.monotonic()
                left = deadline - at
                assert left > 0
                p = subprocess.run(command, cwd=r, env=env, capture_output=True, timeout=min(5, left))
                expected = 0 if variant == 'genuine' else 1
                results.append(dict(member=index, half=label, variant=variant, exit_code=p.returncode,
                    expected=expected, command=command, duration_seconds=round(time.monotonic() - at, 6)))
                assert p.returncode == expected, (index, label, variant, p.returncode)
    assert len(results) == 9
    pins()
except BaseException as ex:
    error = type(ex).__name__ + ': ' + str(ex)[:300]
inventory = []
for p in sorted(root.iterdir()):
    assert p.is_file() and not p.is_symlink()
    inventory.append(dict(path=p.name, sha256=sha(p), bytes=p.stat().st_size))
seal = root / 'PUBLIC_INVENTORY.json'
seal.write_text(json.dumps(dict(public_only=True, private=False, files=inventory), indent=2) + '\n')
duration = round(time.monotonic() - start, 6)
cumulative = round(q['cumulative_seconds'] + duration, 6)
completed = error is None and len(results) == 9 and cumulative <= 120
report = dict(format=stage['format'], completed=completed, error=error, results=results, duration_seconds=duration,
    previous_used_seconds=q['cumulative_seconds'], cumulative_seconds=cumulative, budget_seconds=120,
    controller_sha256=sha(Path(__file__)), stage_sha256=sha(stagep), public_inventory_sha256=sha(seal),
    public_file_count=len(inventory), genuine_halves=6, rejection_cases=3, source=q['core_source'],
    openssl_binary_sha256=sha(openssl), private_key_reads=0, signing_calls=0, socket_calls=0,
    Native_Runtime_Node_calls=0, cross_implementation_direction='Rust-fips204/dalek to OpenSSL',
    adopted_profile=False, independent_security_review=False, whole_goal_completed=False, old_failures_retained=True)
out.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'results'}))
raise SystemExit(0 if completed else 1)
