from pathlib import Path
import os, json, time, hashlib, subprocess, selectors, datetime, signal, re

r = Path.cwd()
assert r == Path('/Users/galaxy/GitHub/rldcoin')
started = time.monotonic()
deadline = started + 120
b = r / 'tmp/default-relay-20260930'
e = r / 'docs/operations/evidence'
name = 'pq-hybrid-tls-composition-v4-20261007'
root = b / (name + '-private')
stagep = e / (name + '-stage.json')
out = e / (name + '-checks.json')
log = b / (name + '.log')
cbinary = b / (name + '-tls-binary')
rbinary = r / 'target/pq-tests-rust198-opt1/debug/rld-hybrid-auth-core-candidate'
assert not any(p.exists() for p in (root, stagep, out, log, cbinary, rbinary))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
source = r / 'tools/fixtures/pq-tls-candidate/transport.c'
crate = r / 'tools/fixtures/pq-hybrid-cross-implementation'
openssl = Path('/opt/homebrew/opt/openssl@3/bin/openssl')
prefix = Path('/opt/homebrew/Cellar/openssl@3/3.6.3')
clang = Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang')
sdk = Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk')
core = json.loads((e / 'core-hybrid-integrated-v9-20261007-core-source.json').read_bytes())
assert core['commitment'] == '4070549af45f5a03c454da30bd15443db41a9f619ab1f0c6941f23e4f9a3d319'
headers = sorted((prefix / 'include/openssl').glob('*.h'))
inputs = [Path(__file__), source, openssl, clang, prefix / 'lib/libssl.3.dylib', prefix / 'lib/libcrypto.3.dylib',
          sdk / 'SDKSettings.json', sdk / 'usr/include/arpa/inet.h', sdk / 'usr/include/sys/socket.h',
          r / 'tools/interstellar_tcp.py', r / 'docs/WHITEPAPER_FREEZE_RECEIPT.json',
          r / 'vectors/pq-hybrid-authorization-v1/openssl-hybrid-public.json',
          e / 'pq-tls-native-v2-20261007-checks.json', e / 'pq-tls-native-v3-20261007-checks.json',
          e / 'core-hybrid-integrated-v9-20261007-checks.json',
          b / 'core-hybrid-integrated-v9-20261007-qualified-test-binary',
          r / 'docs/operations/fixtures/pq-tls-native-v1-20261007/transport.c', *headers,
          *sorted((crate / 'src').rglob('*.rs')), crate / 'Cargo.toml']
protected = {str(p): sha(p) for p in inputs}
protected.update({str(r / v['path']): v['sha256'] for v in core['files']})
receipt = json.loads((r / 'docs/WHITEPAPER_FREEZE_RECEIPT.json').read_bytes())
for f in ('canonical_markdown', 'pdf'):
    protected[str(r.parent / 'rldcoin-website' / receipt[f]['path'])] = receipt[f]['sha256']
old = (r / 'docs/operations/fixtures/pq-tls-native-v1-20261007/transport.c').read_text()
new = source.read_text()
bridge = {}
for label, start, stop in (
    ('peer-policy', 'static int peer_policy(', 'int main('),
    ('TLS-context-policy', '    failure = "fixed TLS policy";', '    struct sockaddr_in address;'),
):
    old_part = old[old.index(start):old.index(stop, old.index(start))]
    new_part = new[new.index(start):new.index(stop, new.index(start))]
    if label == 'peer-policy':
        new_part = new_part[:new_part.index('/* This framing receipt')].rstrip() + '\n'
        old_part = old_part.rstrip() + '\n'
    assert old_part == new_part, label
    bridge[label] = hashlib.sha256(old_part.encode()).hexdigest()
def pins():
    assert all(sha(Path(p)) == h for p, h in protected.items()), 'source/provider/evidence changed'
pins()
stage = dict(format='RLD-PQ-HYBRID-TLS-COMPOSITION-V4',
    recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), budget_seconds=120, attempts=1,
    hypothesis='Actual bounded Core public dual envelope crosses exact mutual hybrid TLS as unchanged complete bytes; '
        'transport acknowledgment cannot authorize a forged inner PQ half. Fresh credentials only. '
        'Probe exact bound, incomplete frame and existing/symlink destination refusal. Actual rld-core decode and AND '
        'verification, independently supplied local trust/epoch/nonce; no Native/Node/Runtime/value state. '
        'Original policy source segments exactly bridge only unchanged policy logic, no transfer of complete new-source qualification.',
    exit='First pin/build/guard error or total120 including build, cases, terminal/seal stops and retains FAIL; no same-input retry.',
    protected_sha256=protected.copy(), core_source=core['commitment'], policy_source_bridge=bridge,
    initial_standalone_lock_sha256=sha(crate / 'Cargo.lock'), public_payload_bound=12288,
    old_failures_retained=True, whole_goal_completed=False)
stagep.write_text(json.dumps(stage, indent=2) + '\n')
results, cases, owned, forced = [], [], [], []
error = None
oldmask = os.umask(0o077)
root.mkdir(mode=0o700)
env = dict(os.environ, OPENSSL_CONF='/dev/null', RUSTUP_TOOLCHAIN='1.98.0', PYTHONDONTWRITEBYTECODE='1')
env.pop('OPENSSL_MODULES', None)
def remaining(limit=120):
    left = deadline - time.monotonic()
    assert left > 0, 'original120 exhausted'
    return min(limit, left)
def record(command, code, output, errors, at):
    with log.open('ab') as stream:
        stream.write(output + errors)
    results.append(dict(command=command, exit_code=code, duration_seconds=round(time.monotonic() - at, 6)))
def run(command, expected=0, stdin=None, limit=120):
    pins()
    at = time.monotonic()
    p = subprocess.Popen(command, cwd=r, env=env, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    owned.append(p)
    output, errors = p.communicate(input=stdin, timeout=remaining(limit))
    record(command, p.returncode, output, errors, at)
    if expected is not None:
        assert p.returncode == expected, ('unexpected exit', command[0], p.returncode, expected)
    return output, errors, p.returncode
def exchange(label, src, dest, expected=0, raw=None):
    pins()
    at = time.monotonic()
    command = [str(cbinary), 'server', '0', str(root / 'server-cert.pem'), str(root / 'server-key.pem'),
        str(root / 'client-cert.pem'), sha(root / 'client-cert.der'), str(dest)]
    server = subprocess.Popen(command, cwd=r, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    owned.append(server)
    with selectors.DefaultSelector() as selector:
        selector.register(server.stdout, selectors.EVENT_READ)
        assert selector.select(remaining(3.5)), 'server readiness unavailable'
        ready = server.stdout.readline()
    assert ready.startswith(b'READY '), 'server rejected before ready'
    port = int(ready.split()[1])
    if raw is None:
        client = [str(cbinary), 'client', str(port), str(root / 'client-cert.pem'), str(root / 'client-key.pem'),
            str(root / 'server-cert.pem'), sha(root / 'server-cert.der'), str(src)]
        coutput, cerrors, ccode = run(client, expected, limit=4)
    else:
        client = [str(openssl), 's_client', '-connect', '127.0.0.1:' + str(port), '-brief', '-no_ign_eof',
            '-verify_return_error', '-CAfile', str(root / 'server-cert.pem'), '-cert', str(root / 'client-cert.pem'),
            '-key', str(root / 'client-key.pem'), '-groups', 'X25519MLKEM768', '-sigalgs', 'mldsa87',
            '-tls1_3', '-provider', 'default']
        coutput, cerrors, ccode = run(client, None, raw, 4)
    output, errors = server.communicate(timeout=remaining(4))
    record(command, server.returncode, ready + output, errors, at)
    assert server.returncode == expected, ('server unexpected', label, server.returncode)
    if expected == 0:
        reports = [json.loads(v) for v in (coutput, output)]
        assert all(v['group'] == 'X25519MLKEM768' and v['tls'] == 'TLSv1.3'
            and v['peer_algorithm'] == 'ML-DSA-87' and v['cipher'] == 'TLS_AES_256_GCM_SHA384'
            and v['public_payload_verified'] and not v['public_marker_verified']
            and v['public_payload_bytes'] == src.stat().st_size
            and v['implementation_source'] == sha(source) for v in reports)
        assert dest.read_bytes() == src.read_bytes()
    else:
        assert b'public_payload_verified' not in coutput + output
        assert b'bounded public payload exchange' in errors
    cases.append(dict(case=label, server_exit=server.returncode, client_exit=ccode,
        acknowledged=expected == 0, payload_bytes=src.stat().st_size if src else None,
        payload_sha256=sha(dest) if dest.is_file() else None, loopback_port=port))
try:
    manifest = str(crate / 'Cargo.toml')
    run(['cargo', 'generate-lockfile', '--manifest-path', manifest, '--offline'])
    protected[str(crate / 'Cargo.lock')] = sha(crate / 'Cargo.lock')
    run(['cargo', 'fmt', '--manifest-path', manifest, '--all', '--check'])
    common = ['--manifest-path', manifest, '--locked', '--offline', '--target-dir', 'target/pq-tests-rust198-opt1',
        '--config', 'profile.dev.opt-level=1', '--config', 'profile.dev.debug-assertions=true',
        '--config', 'profile.dev.overflow-checks=true']
    run(['cargo', 'clippy', *common, '--all-targets', '--no-deps', '--', '-D', 'warnings'])
    run(['cargo', 'build', *common, '--bin', 'rld-hybrid-auth-core-candidate'])
    assert core['commitment'].encode() in rbinary.read_bytes()
    protected[str(rbinary)] = sha(rbinary)
    build = [str(clang), '-isysroot', str(sdk), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pedantic',
        '-I' + str(prefix / 'include'), '-L' + str(prefix / 'lib'), '-Wl,-rpath,' + str(prefix / 'lib'),
        '-DRLD_TLS_CANDIDATE_SOURCE="' + sha(source) + '"', str(source), '-lssl', '-lcrypto', '-o', str(cbinary)]
    run(build)
    assert sha(source).encode() in cbinary.read_bytes()
    protected[str(cbinary)] = sha(cbinary)
    for role in ('server', 'client'):
        run([str(openssl), 'genpkey', '-algorithm', 'ML-DSA-87', '-provider', 'default', '-out', str(root / (role + '-key.pem'))])
        run([str(openssl), 'req', '-new', '-x509', '-key', str(root / (role + '-key.pem')),
            '-out', str(root / (role + '-cert.pem')), '-days', '90', '-subj', '/CN=RLD-PQ-TLS-CANDIDATE-' + role,
            '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
            '-addext', 'extendedKeyUsage=serverAuth,clientAuth', '-addext', 'subjectAltName=IP:127.0.0.1', '-provider', 'default'])
        run([str(openssl), 'x509', '-in', str(root / (role + '-cert.pem')), '-outform', 'DER', '-out', str(root / (role + '-cert.der'))])
        for suffix in ('key.pem', 'cert.pem', 'cert.der'):
            protected[str(root / (role + '-' + suffix))] = sha(root / (role + '-' + suffix))
    vectors = json.loads((r / 'vectors/pq-hybrid-authorization-v1/openssl-hybrid-public.json').read_bytes())
    intent = json.loads(bytes.fromhex(vectors['intent.bin']).split(b'\0', 1)[1])
    envelope = dict(ed_signature=vectors['ed-signature.bin'], intent=intent, pq_signature=vectors['pq-signature.bin'],
        profile='RLDCOIN-HYBRID-AUTH-CANDIDATE-V1')
    policy = dict(profile=envelope['profile'], currency_root='01' * 32, region_root='02' * 32,
        purpose='PAYMENT', valid_from_epoch=1, valid_until_epoch=9,
        ed_public_key=bytes.fromhex(vectors['ed-public.der'])[12:].hex(),
        pq_public_key=bytes.fromhex(vectors['pq-public.der'])[22:].hex(),
        current_epoch=1, next_nonce=1, policy_trust='CURRENT_AND_TRUSTED')
    policyfile = root / 'caller-trusted-public-policy.json'
    policyfile.write_text(json.dumps(policy, sort_keys=True, separators=(',', ':')))
    protected[str(policyfile)] = sha(policyfile)
    for label, pq, expected in [('genuine-public-Core-envelope', vectors['pq-signature.bin'], 0),
                                ('forged-inner-PQ-transported-Core-refused', vectors['pq-altered-signature.bin'], 1)]:
        packet = dict(envelope, pq_signature=pq)
        src, dest = root / (label + '-source.json'), root / (label + '-received.json')
        src.write_text(json.dumps(packet, sort_keys=True, separators=(',', ':')))
        protected[str(src)] = sha(src)
        exchange(label, src, dest)
        protected[str(dest)] = sha(dest)
        output, errors, code = run([str(rbinary), str(policyfile), str(dest)], expected)
        assert core['commitment'].encode() in output
        if expected:
            assert b'post-quantum key or signature invalid' in errors
        cases[-1]['actual_Core_exit'] = code
    good = root / 'genuine-public-Core-envelope-source.json'
    existing = root / 'existing-destination.json'
    existing.write_bytes(b'preserved sentinel')
    protected[str(existing)] = sha(existing)
    exchange('existing-destination-refused', good, existing, 1)
    target = root / 'symlink-target.json'
    target.write_bytes(b'preserved symlink target')
    protected[str(target)] = sha(target)
    link = root / 'symlink-destination.json'
    link.symlink_to(target.name)
    exchange('symlink-destination-refused', good, link, 1)
    assert link.is_symlink() and os.readlink(link) == target.name
    for label, wire in [('oversize-frame-refused', (12289).to_bytes(4, 'big')),
                        ('truncated-frame-refused', (100).to_bytes(4, 'big') + b'partial')]:
        dest = root / (label + '.json')
        exchange(label, None, dest, 1, wire)
        assert not dest.exists()
    assert len(cases) == 6
    pins()
except BaseException as ex:
    error = type(ex).__name__ + ': ' + str(ex)[:500]
finally:
    for p in owned:
        if p.poll() is None:
            forced.append(p.pid)
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=2)
    os.umask(oldmask)
pin_error = None
try:
    pins()
except BaseException as ex:
    pin_error = type(ex).__name__ + ': ' + str(ex)[:200]
files = []
for p in sorted(root.iterdir()):
    st = p.lstat()
    assert p.is_symlink() or p.is_file()
    files.append(dict(path=p.name, bytes=st.st_size, mode=oct(st.st_mode & 0o777), uid=st.st_uid,
        inode=st.st_ino, mtime_ns=st.st_mtime_ns, link_target=os.readlink(p) if p.is_symlink() else None,
        sha256=None if p.is_symlink() else sha(p)))
seal = root / 'PRIVATE_INVENTORY.json'
seal.write_text(json.dumps(dict(format='RLD-PQ-TLS-PRIVATE-INVENTORY-V1', private=True, files=files), indent=2) + '\n')
duration = round(time.monotonic() - started, 6)
completed = error is None and pin_error is None and duration <= 120 and not forced and all(p.poll() is not None for p in owned)
report = dict(format=stage['format'], completed=completed, duration_seconds=duration, budget_seconds=120, attempts=1,
    error=error, pin_error=pin_error, results=results, cases=cases, forced_owned_processes=forced,
    owned_processes_stopped=all(p.poll() is not None for p in owned), controller_sha256=sha(Path(__file__)),
    stage_sha256=sha(stagep), log_sha256=sha(log) if log.exists() else None, source_sha256=sha(source),
    actual_TLS_binary_sha256=sha(cbinary) if cbinary.exists() else None,
    actual_Core_adapter_binary_sha256=sha(rbinary) if rbinary.exists() else None,
    core_source=core['commitment'], final_standalone_lock_sha256=sha(crate / 'Cargo.lock'),
    private_inventory_sha256=sha(seal), private_file_count=len(files), budget_exhausted=duration > 120,
    source_policy_bridge=bridge, all_current_source_six_TLS_policy_cases_requalified=False,
    native_Node_Runtime_calls=0, loopback_only=True, transport_is_value_authorization=False,
    adopted_profile=False, independent_review=False, physical=False, whole_goal_completed=False,
    old_failures_retained=True)
out.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'results'}))
raise SystemExit(0 if completed else 1)
