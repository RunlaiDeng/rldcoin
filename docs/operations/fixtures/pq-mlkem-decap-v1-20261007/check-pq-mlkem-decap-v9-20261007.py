from pathlib import Path
import os, json, hashlib, time, subprocess, datetime, signal
r = Path.cwd()
assert r == Path('/Users/galaxy/GitHub/rldcoin')
b, e = r / 'tmp/default-relay-20260930', r / 'docs/operations/evidence'
name = 'pq-mlkem-decap-v9-20261007'
root, stagep, out, binary, log = b / (name + '-private'), e / (name + '-stage.json'), e / (name + '-checks.json'), b / (name + '-binary'), b / (name + '.log')
assert not any(p.exists() for p in (root, stagep, out, binary, log))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
source = r / 'tools/fixtures/pq-tls-candidate/mlkem768_kat.c'
official = json.loads((e / 'pq-mlkem-official-source-v8-20261007-checks.json').read_bytes())
assert official['completed'] and official['commit'] == 'a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324'
corpus = b / 'pq-mlkem-official-source-v8-20261007-private'
for file in official['files']: assert sha(r / file['path']) == file['sha256']
prefix = Path('/opt/homebrew/Cellar/openssl@3/3.6.3')
clang = Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang')
sdk = Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk')
headers = sorted((prefix / 'include/openssl').glob('*.h'))
core = json.loads((e / 'core-hybrid-quorum-integrated-v11-20261007-core-source.json').read_bytes())
inputs = [Path(__file__), source, clang, sdk / 'SDKSettings.json', sdk / 'usr/include/sys/stat.h', prefix / 'lib/libcrypto.3.dylib',
    corpus / 'prompt.json', corpus / 'expectedResults.json', e / 'pq-mlkem-official-source-v8-20261007-checks.json',
    r / 'tools/fixtures/pq-tls-candidate/transport.c', b / 'pq-hybrid-tls-composition-v4-20261007-tls-binary',
    e / 'pq-quorum-carriage-reference-v1-qualified-profile-20261007.json', r / 'docs/WHITEPAPER_FREEZE_RECEIPT.json', *headers]
protected = {str(p): sha(p) for p in inputs}
protected.update({str(r / v['path']): v['sha256'] for v in core['files']})
def pins(): assert all(sha(Path(p)) == h for p, h in protected.items())
build = [str(clang), '-isysroot', str(sdk), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pedantic',
    '-I' + str(prefix / 'include'), '-L' + str(prefix / 'lib'), '-Wl,-rpath,' + str(prefix / 'lib'),
    '-DRLD_MLKEM_CANDIDATE_SOURCE="' + sha(source) + '"', str(source), '-lcrypto', '-o', str(binary)]
stage = dict(format='RLD-PQ-MLKEM-DECAP-V9', recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    budget_seconds=120, attempts=1, protected_sha256=protected, build=build, official_commit=official['commit'],
    hypothesis='Actual supported default OpenSSL EVP_PKEY_fromdata priv/ML-KEM-768 and decapsulate must exactly match all10 '
        'official expanded-key group5 cases86..95, including5 genuine and5 implicit rejection independently classified with '
        'SHAKE256(z||c). One altered genuine ciphertext must match independent implicit-rejection bytes and differ from old '
        'genuine secret; library success cannot grant peer/ciphertext authenticity. Three exact-length and symlink inputs refuse '
        'before primitive import. Known published official test keys only, no new keygen, local real keys, TLS/socket/Native/Node/Runtime. '
        'One120 includes compile,16 actual checks, source guards and retained typed inventory. Separate downloadV8 never crypto qualification.',
    exit='First source/compile/import/API/expected-byte/guard error or original120 stops and retains FAIL; no unknown treated as correctness, no unchanged retry.',
    core_source=core['commitment'], public_known_standard_test_keys=True, real_wallet_TLS_Native_key_reads=0,
    cryptographic_secret_output=False, adopted_profile=False, whole_goal_completed=False)
pins(); stagep.write_text(json.dumps(stage, indent=2) + '\n')
start = time.monotonic(); deadline = start + 120
oldmask = os.umask(0o077); root.mkdir(mode=0o700)
results, cases, owned, forced = [], [], [], []
error = None
env = dict(os.environ, OPENSSL_CONF='/dev/null'); env.pop('OPENSSL_MODULES', None)
def run(command, expected=0):
    pins(); at = time.monotonic(); left = deadline - at; assert left > 0
    p = subprocess.Popen(command, cwd=r, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    owned.append(p); output, errors = p.communicate(timeout=min(15, left))
    with log.open('ab') as f: f.write(output + errors)
    results.append(dict(command=command, exit_code=p.returncode, expected=expected, duration_seconds=round(time.monotonic() - at, 6)))
    assert p.returncode == expected, ('unexpected primitive exit', p.returncode, expected)
    if command[0] == str(binary) and expected == 0:
        x = json.loads(output); assert x['expected_bytes_match'] and not x['api_success_is_authentication'] and x['implementation_source'] == sha(source)
    return output, errors
def file(name, raw):
    p = root / name; assert not p.exists(); p.write_bytes(raw); protected[str(p)] = sha(p); return p
try:
    run(build); assert sha(source).encode() in binary.read_bytes(); protected[str(binary)] = sha(binary)
    prompt = json.loads((corpus / 'prompt.json').read_bytes()); expected = json.loads((corpus / 'expectedResults.json').read_bytes())
    group = next(g for g in prompt['testGroups'] if g['tgId'] == 5)
    assert group['parameterSet'] == 'ML-KEM-768' and group['function'] == 'decapsulation' and len(group['tests']) == 10
    answers = {t['tcId']: t for g in expected['testGroups'] if g['tgId'] == 5 for t in g['tests']}
    genuine = None
    for test in group['tests']:
        case = test['tcId']; dk, c, k = bytes.fromhex(test['dk']), bytes.fromhex(test['c']), bytes.fromhex(answers[case]['k'])
        assert len(dk) == 2400 and len(c) == 1088 and len(k) == 32
        fallback = hashlib.shake_256(dk[-32:] + c).digest(32)
        implicit = fallback == k
        paths = (file(str(case) + '-official-dk.bin', dk), file(str(case) + '-ciphertext.bin', c), file(str(case) + '-expected.bin', k))
        run([str(binary), *map(str, paths)])
        cases.append(dict(tcId=case, official=True, expected_implicit_rejection=implicit, exact_expected_bytes_matched=True))
        if genuine is None and not implicit: genuine = (dk, c, k, paths)
    assert sum(v['expected_implicit_rejection'] for v in cases) == 5 and genuine is not None
    dk, c, k, paths = genuine
    changed = bytes([c[0] ^ 1]) + c[1:]
    fallback = hashlib.shake_256(dk[-32:] + changed).digest(32); assert fallback != k
    changedp = file('changed-ciphertext.bin', changed); fallbackp = file('independent-implicit-rejection-expected.bin', fallback)
    run([str(binary), str(paths[0]), str(changedp), str(fallbackp)])
    cases.append(dict(case='changed-ciphertext-exact-independent-implicit-rejection', primitive_API_success_is_authentication=False, expected_bytes_matched=True))
    run([str(binary), str(paths[0]), str(changedp), str(paths[2])], 1)
    cases.append(dict(case='changed-ciphertext-old-genuine-secret-refused', comparator_exit=1))
    for index, raw in enumerate((dk[:-1], c[:-1], k[:-1])):
        short = file('short-input' + str(index) + '.bin', raw); alternate = list(paths); alternate[index] = short
        run([str(binary), *map(str, alternate)], 2); cases.append(dict(case='short-input-' + str(index), unavailable_exit=2))
    link = root / 'symlink-dk.bin'; link.symlink_to(paths[0].name)
    run([str(binary), str(link), str(paths[1]), str(paths[2])], 2)
    cases.append(dict(case='symlink-dk-refused', unavailable_exit=2))
    assert len(cases) == 16; pins()
except BaseException as ex:
    error = type(ex).__name__ + ': ' + str(ex)[:300]
finally:
    for p in owned:
        if p.poll() is None:
            forced.append(p.pid); os.killpg(p.pid, signal.SIGTERM)
            try: p.wait(timeout=2)
            except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=2)
    os.umask(oldmask)
pin_error = None
try: pins()
except BaseException as ex: pin_error = type(ex).__name__ + ': ' + str(ex)[:200]
files = []
for p in sorted(root.iterdir()):
    st = p.lstat(); assert p.is_file() or p.is_symlink()
    files.append(dict(path=p.name, bytes=st.st_size, sha256=None if p.is_symlink() else sha(p),
        mode=oct(st.st_mode & 0o777), uid=st.st_uid, inode=st.st_ino, mtime_ns=st.st_mtime_ns,
        link_target=os.readlink(p) if p.is_symlink() else None))
seal = root / 'PRIVATE_INVENTORY.json'; seal.write_text(json.dumps(dict(private=True, known_public_official_test_material_only=True, files=files), indent=2) + '\n')
duration = round(time.monotonic() - start, 6)
completed = error is None and pin_error is None and not forced and len(cases) == 16 and duration <= 120
report = dict(format=stage['format'], completed=completed, duration_seconds=duration, budget_seconds=120, attempts=1,
    error=error, pin_error=pin_error, results=results, cases=cases, official_group=5, parameter='ML-KEM-768',
    official_commit=official['commit'], controller_sha256=sha(Path(__file__)), stage_sha256=sha(stagep),
    source_sha256=sha(source), actual_binary_sha256=sha(binary) if binary.exists() else None,
    private_inventory_sha256=sha(seal), retained_file_count=len(files), log_sha256=sha(log) if log.exists() else None,
    forced_owned_processes=forced, owned_processes_stopped=all(p.poll() is not None for p in owned),
    core_source=core['commitment'], core_existing_TLS_unchanged=pin_error is None,
    genuine_official_cases=5, implicit_rejection_official_cases=5, full_FIPS203_KAT=False,
    encapsulation_keygen_checks_qualified=False, constant_time_qualification=False, different_KEM_implementation=False,
    real_wallet_TLS_Native_key_reads=0, key_generation_calls=0, socket_calls=0, Native_Runtime_Node_calls=0,
    adopted_profile=False, independent_security_review=False, physical=False, whole_goal_completed=False, old_failures_retained=True)
out.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k != 'results'}))
raise SystemExit(0 if completed else 1)
