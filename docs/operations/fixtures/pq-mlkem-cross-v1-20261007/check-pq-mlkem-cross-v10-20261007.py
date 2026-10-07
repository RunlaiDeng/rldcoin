from pathlib import Path
import os, json, hashlib, time, subprocess, datetime, signal, tomllib
r = Path.cwd()
assert r == Path('/Users/galaxy/GitHub/rldcoin')
b, e = r / 'tmp/default-relay-20260930', r / 'docs/operations/evidence'
name = 'pq-mlkem-cross-v10-20261007'
stagep, out, log = e / (name + '-stage.json'), e / (name + '-checks.json'), b / (name + '.log')
binary = r / 'target/pq-tests-rust198-opt1/debug/rld-ml-kem-768-kat-candidate'
assert not any(p.exists() for p in (stagep, out, log, binary))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
crate = r / 'tools/fixtures/pq-hybrid-cross-implementation'
priorp = e / 'pq-mlkem-decap-v9-20261007-checks.json'
prior = json.loads(priorp.read_bytes())
assert prior['completed'] and len(prior['cases']) == 16 and len(prior['results']) == 17
oldroot = b / 'pq-mlkem-decap-v9-20261007-private'
seal = oldroot / 'PRIVATE_INVENTORY.json'
inventory = json.loads(seal.read_bytes())
core = json.loads((e / 'core-hybrid-quorum-integrated-v11-20261007-core-source.json').read_bytes())
inputs = [Path(__file__), crate / 'Cargo.toml', *sorted((crate / 'src').rglob('*.rs')),
    priorp, e / 'pq-mlkem-decap-v9-20261007-stage.json', b / 'pq-mlkem-decap-v9-20261007-binary', seal,
    r / 'tools/fixtures/pq-tls-candidate/mlkem768_kat.c', r / 'tools/fixtures/pq-tls-candidate/transport.c',
    b / 'pq-hybrid-tls-composition-v4-20261007-tls-binary', r / 'docs/WHITEPAPER_FREEZE_RECEIPT.json']
protected = {str(p): sha(p) for p in inputs}
protected.update({str(r / v['path']): v['sha256'] for v in core['files']})
links = {}
for item in inventory['files']:
    p = oldroot / item['path']
    if item['link_target'] is None:
        assert sha(p) == item['sha256']; protected[str(p)] = item['sha256']
    else:
        assert p.is_symlink() and os.readlink(p) == item['link_target']; links[str(p)] = item['link_target']
initial_lock = tomllib.loads((crate / 'Cargo.lock').read_text())
initial_packages = {(v['name'], v['version'], v.get('source'), v.get('checksum')) for v in initial_lock['package']}
def pins():
    assert all(sha(Path(p)) == h for p, h in protected.items())
    assert all(Path(p).is_symlink() and os.readlink(p) == target for p, target in links.items())
stage = dict(format='RLD-PQ-MLKEM-CROSS-V10', recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    budget_seconds=120, attempts=1, protected_sha256=protected, initial_lock_sha256=sha(crate / 'Cargo.lock'),
    hypothesis='Different pure Rust fips203 exact0.4.3/ml-kem-768 public SerDes/Decaps API on same complete official group5 '
        'cases86..95 and six negative/implicit-rejection guards as already-qualified exact C/OpenSSL V9. Reuse C outcomes; '
        'only read immutable known published standard-vector material, no old real keys/custody. No secret Debug/output. '
        'Standalone candidate dependency only; required crate download/checksum/source inventory, strict/offline build and '
        '16 actual Rust cases inside once120. Preserve existing locked package versions; add only exact fips203. '
        'API success for malformed ciphertext cannot authenticate peers. Core182d728/TLS unchanged and no Native/value retests.',
    exit='First dependency/checksum/version/source/static/compile/expected-byte error or original120 stops retaining FAIL; no warning exemption, same-input retry or broadened qualification.',
    known_standard_key_inputs_only=True, real_wallet_TLS_Native_key_reads=0, source_only_network_dependency_download=True,
    adopted_profile=False, independent_review=False, whole_goal_completed=False)
pins(); stagep.write_text(json.dumps(stage, indent=2) + '\n')
started = time.monotonic(); deadline = started + 120
results, cases, owned, forced, package_source = [], [], [], [], []
error = None
env = dict(os.environ, RUSTUP_TOOLCHAIN='1.98.0', PYTHONDONTWRITEBYTECODE='1')
def run(command, expected=0):
    pins(); at = time.monotonic(); left = deadline - at; assert left > 0
    p = subprocess.Popen(command, cwd=r, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    owned.append(p); output, errors = p.communicate(timeout=left)
    with log.open('ab') as f: f.write(output + errors)
    results.append(dict(command=command, exit_code=p.returncode, expected=expected, duration_seconds=round(time.monotonic() - at, 6)))
    assert p.returncode == expected, ('unexpected exit', command[0], p.returncode, expected)
    if command[0] == str(binary) and expected == 0:
        assert b'expected bytes matched' in output and b'API success is not authentication' in output
    return output, errors
try:
    manifest = str(crate / 'Cargo.toml')
    run(['cargo', 'fetch', '--manifest-path', manifest])
    resolved = tomllib.loads((crate / 'Cargo.lock').read_text())
    packages = {(v['name'], v['version'], v.get('source'), v.get('checksum')) for v in resolved['package']}
    assert initial_packages <= packages, 'existing locked package changed'
    added = packages - initial_packages; assert len(added) == 1 and next(iter(added))[0:2] == ('fips203', '0.4.3')
    pkg = next(p for p in resolved['package'] if p['name'] == 'fips203')
    archives = list(Path('/Users/galaxy/.cargo/registry/cache').glob('*/fips203-0.4.3.crate'))
    sources = list(Path('/Users/galaxy/.cargo/registry/src').glob('*/fips203-0.4.3'))
    assert len(archives) == len(sources) == 1 and sha(archives[0]) == pkg['checksum']
    protected[str(archives[0])] = sha(archives[0]); protected[str(crate / 'Cargo.lock')] = sha(crate / 'Cargo.lock')
    src = sources[0]
    assert tomllib.loads((src / 'Cargo.toml').read_text())['package']['version'] == '0.4.3'
    for p in [src / 'Cargo.toml', *sorted((src / 'src').rglob('*.rs'))]:
        assert p.is_file() and not p.is_symlink()
        protected[str(p)] = sha(p)
        package_source.append(dict(path=str(p), sha256=sha(p), bytes=p.stat().st_size))
    run(['cargo', 'fmt', '--manifest-path', manifest, '--all', '--check'])
    flags = ['--manifest-path', manifest, '--locked', '--offline', '--target-dir', 'target/pq-tests-rust198-opt1',
        '--config', 'profile.dev.opt-level=1', '--config', 'profile.dev.debug-assertions=true', '--config', 'profile.dev.overflow-checks=true']
    run(['cargo', 'clippy', *flags, '--all-targets', '--no-deps', '--', '-D', 'warnings'])
    run(['cargo', 'build', *flags, '--bin', 'rld-ml-kem-768-kat-candidate'])
    protected[str(binary)] = sha(binary)
    for index, item in enumerate(prior['results'][1:]):
        command = [str(binary), *item['command'][1:]]
        run(command, item['expected'])
        cases.append(dict(prior['cases'][index], actual_Rust_exit=item['expected'], original_C_expected=item['expected']))
    assert len(cases) == 16; pins()
except BaseException as ex:
    error = type(ex).__name__ + ': ' + str(ex)[:300]
finally:
    for p in owned:
        if p.poll() is None:
            forced.append(p.pid); os.killpg(p.pid, signal.SIGTERM)
            try: p.wait(timeout=2)
            except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=2)
pin_error = None
try: pins()
except BaseException as ex: pin_error = type(ex).__name__ + ': ' + str(ex)[:200]
duration = round(time.monotonic() - started, 6)
completed = error is None and pin_error is None and not forced and len(cases) == 16 and duration <= 120
report = dict(format=stage['format'], completed=completed, duration_seconds=duration, budget_seconds=120, attempts=1,
    error=error, pin_error=pin_error, results=results, cases=cases, forced_owned_processes=forced,
    owned_processes_stopped=all(p.poll() is not None for p in owned), controller_sha256=sha(Path(__file__)),
    stage_sha256=sha(stagep), actual_binary_sha256=sha(binary) if binary.exists() else None,
    lock_sha256=sha(crate / 'Cargo.lock'), package_source=package_source,
    crate_checksum=sha(archives[0]) if package_source else None, source_implementation='fips2030.4.3/ml-kem-768',
    Core_source=core['commitment'], real_wallet_TLS_Native_key_reads=0, key_generation_calls=0,
    socket_calls=0, Native_Runtime_Node_calls=0, C_primitive_retests=0, full_FIPS203_KAT=False,
    different_KEM_implementation=completed, constant_time_qualification=False, adopted_profile=False,
    independent_review=False, physical=False, whole_goal_completed=False, old_failures_retained=True)
out.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: v for k, v in report.items() if k not in ('results', 'package_source')}))
raise SystemExit(0 if completed else 1)
