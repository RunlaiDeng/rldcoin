from pathlib import Path
import os, json, hashlib, time, subprocess, datetime, signal
r = Path.cwd()
assert r == Path('/Users/galaxy/GitHub/rldcoin')
b, e = r / 'tmp/default-relay-20260930', r / 'docs/operations/evidence'
name = 'pq-mlkem-keygen-v14-20261007'
root, stagep, out, binary, log = b / (name + '-private'), e / (name + '-stage.json'), e / (name + '-checks.json'), b / (name + '-binary'), b / (name + '.log')
assert not any(p.exists() for p in (root, stagep, out, binary, log))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
priorp=e/'pq-mlkem-keygen-v13-20261007-checks.json'
prior=json.loads(priorp.read_bytes());assert not prior['completed'] and prior['private_files']==0 and len(prior['cases'])==0
used=prior['duration_seconds'];binary=b/'pq-mlkem-keygen-v13-20261007-binary'
assert sha(binary)==prior['actual_C_binary_sha256']
source = r / 'tools/fixtures/pq-tls-candidate/mlkem768_keygen_kat.c'
crate = r / 'tools/fixtures/pq-hybrid-cross-implementation'
rust_source = crate / 'src/bin/rld-ml-kem-768-keygen-kat-candidate.rs'
rust_binary = r / 'target/pq-tests-rust198-opt1/debug/rld-ml-kem-768-keygen-kat-candidate'
assert not rust_binary.exists()
official = json.loads((e / 'pq-mlkem-official-source-v8-20261007-checks.json').read_bytes())
assert official['completed'] and official['commit'] == 'a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324'
corpus = b / 'pq-mlkem-official-source-v8-20261007-private'
for file in official['files']: assert sha(r / file['path']) == file['sha256']
prefix = Path('/opt/homebrew/Cellar/openssl@3/3.6.3')
clang = Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang')
sdk = Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk')
headers = sorted((prefix / 'include/openssl').glob('*.h'))
core = json.loads((e / 'core-hybrid-quorum-integrated-v11-20261007-core-source.json').read_bytes())
inputs = [Path(__file__), priorp, binary, b / "pq-mlkem-keygen-v13-failed-source-20261007.rs", source, rust_source, crate / "Cargo.toml", crate / "Cargo.lock", *sorted((crate / "src").rglob("*.rs")), clang, sdk / 'SDKSettings.json', sdk / 'usr/include/sys/stat.h', prefix / 'lib/libcrypto.3.dylib',
    corpus / 'prompt.json', corpus / 'expectedResults.json', e / 'pq-mlkem-official-source-v8-20261007-checks.json',
    r / 'tools/fixtures/pq-tls-candidate/transport.c', b / 'pq-hybrid-tls-composition-v4-20261007-tls-binary',
    e / 'pq-quorum-carriage-reference-v1-qualified-profile-20261007.json', r / 'docs/WHITEPAPER_FREEZE_RECEIPT.json', *headers]
protected = {str(p): sha(p) for p in inputs}
protected.update({str(r / v['path']): v['sha256'] for v in core['files']})
for item in json.loads((e / 'pq-mlkem-cross-v10-20261007-checks.json').read_bytes())['package_source']:
    protected[item['path']] = item['sha256']
keygen_corpus = b / 'pq-mlkem-keygen-source-v12-20261007-private'
source_schema = e / 'pq-mlkem-keygen-source-schema-v2-20261007-checks.json'
source_outcome = json.loads(source_schema.read_bytes()); assert source_outcome['completed']
protected[str(source_schema)] = sha(source_schema)
for t in source_outcome['files']:
    p = r / t['path']; assert sha(p) == t['sha256']; protected[str(p)] = t['sha256']
def pins(): assert all(sha(Path(p)) == h for p, h in protected.items())
build = [str(clang), '-isysroot', str(sdk), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pedantic',
    '-I' + str(prefix / 'include'), '-L' + str(prefix / 'lib'), '-Wl,-rpath,' + str(prefix / 'lib'),
    '-DRLD_MLKEM_CANDIDATE_SOURCE="' + sha(source) + '"', str(source), '-lcrypto', '-o', str(binary)]
stage = dict(format='RLD-PQ-MLKEM-KEYGEN-V14', recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    budget_seconds=120, attempts=1, protected_sha256=protected, build=build, official_commit=official['commit'],
    hypothesis='Known official ML-KEM768 group2 d/z must generate complete ek1184/dk2400 exactly with supported OpenSSL3.6.3 seeded generate and pinned Rust fips2030.4.3 KeyGen APIs. Both engines must match all10 exact2400-byte group9 checks; independent stored-H mismatch and noncanonical embedded-ek with recomputed H refuse. Wrong expected ek/dk, four short inputs/symlink refuse. All88 comparisons/build/seal in original120 minus prior strict-unused-import failure1.433975; unchanged C compile reused, no C rebuild. Standard public test seeds only, no real keys, no production RNG qualification or prior encap/decap/TLS/Native reruns.',
    exit='First source/compile/API/key-check/expected-byte/guard error or original120 stops retaining FAIL; no exemptions/retry/deadline extension.',
    core_source=core['commitment'], public_known_standard_test_keys=True, real_wallet_TLS_Native_key_reads=0,
    cryptographic_secret_output=False, adopted_profile=False, whole_goal_completed=False)
pins(); stagep.write_text(json.dumps(stage, indent=2) + '\n')
start = time.monotonic(); deadline = start + 120 - used
oldmask = os.umask(0o077); root.mkdir(mode=0o700)
results, cases, owned, forced = [], [], [], []
error = None
env = dict(os.environ, OPENSSL_CONF='/dev/null', RUSTUP_TOOLCHAIN='1.98.0', PYTHONDONTWRITEBYTECODE='1'); env.pop('OPENSSL_MODULES', None)
def run(command, expected=0):
    pins(); at = time.monotonic(); left = deadline - at; assert left > 0
    p = subprocess.Popen(command, cwd=r, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    owned.append(p); output, errors = p.communicate(timeout=left)
    with log.open('ab') as f: f.write(output + errors)
    results.append(dict(command=command, exit_code=p.returncode, expected=expected, duration_seconds=round(time.monotonic() - at, 6)))
    assert p.returncode == expected, ('unexpected primitive exit', p.returncode, expected)
    if command[0] == str(binary) and expected == 0:
        x = json.loads(output); assert x['expected_bytes_match'] and not x['api_success_is_authentication'] and x['implementation_source'] == sha(source)
    if command[0] == str(rust_binary) and expected == 0:
        assert b"expected bytes matched" in output and b"API success is not authentication" in output
    return output, errors
def file(name, raw):
    p = root / name; assert not p.exists(); p.write_bytes(raw); protected[str(p)] = sha(p); return p
try:
    assert sha(source).encode() in binary.read_bytes(); protected[str(binary)] = sha(binary)
    manifest = str(crate / 'Cargo.toml')
    flags = ['--manifest-path', manifest, '--locked', '--offline', '--target-dir', 'target/pq-tests-rust198-opt1', '--config', 'profile.dev.opt-level=1', '--config', 'profile.dev.debug-assertions=true', '--config', 'profile.dev.overflow-checks=true']
    run(['cargo', 'fmt', '--manifest-path', manifest, '--all', '--check'])
    run(['cargo', 'clippy', *flags, '--all-targets', '--no-deps', '--', '-D', 'warnings'])
    run(['cargo', 'build', *flags, '--bin', rust_binary.name]); protected[str(rust_binary)] = sha(rust_binary)
    prompt = json.loads((keygen_corpus / 'prompt.json').read_bytes()); expected = json.loads((keygen_corpus / 'expectedResults.json').read_bytes())
    def both(paths, expect, label):
        for engine in (binary,rust_binary):
            run([str(engine),*map(str,paths)],expect)
            cases.append(dict(case=label,engine=engine.name,expected_exit=expect,actual_exit=expect))
    group = next(g for g in prompt['testGroups'] if g['tgId']==2)
    assert group['parameterSet']=='ML-KEM-768' and len(group['tests'])==25
    answers={t['tcId']:t for g in expected['testGroups'] if g['tgId']==2 for t in g['tests']}
    first=None
    for t in group['tests']:
        case=t['tcId']; answer=answers[case]
        raw=[bytes.fromhex(t['d']),bytes.fromhex(t['z']),bytes.fromhex(answer['ek']),bytes.fromhex(answer['dk'])]
        assert list(map(len,raw))==[32,32,1184,2400]
        paths=[file(str(case)+'-'+suffix+'.bin',v) for suffix,v in zip(('d','z','ek','dk'),raw)]
        both(paths,0,'official-keygen-'+str(case))
        if first is None:first=(raw,paths)
    prompt=json.loads((corpus/'prompt.json').read_bytes()); expected=json.loads((corpus/'expectedResults.json').read_bytes())
    group=next(g for g in prompt['testGroups'] if g['tgId']==9)
    answers={t['tcId']:t['testPassed'] for g in expected['testGroups'] if g['tgId']==9 for t in g['tests']}
    assert len(group['tests'])==10 and sum(answers.values())==5
    for t in group['tests']:
        raw=bytes.fromhex(t['dk']);assert len(raw)==2400
        both(['check',file('dkcheck-'+str(t['tcId'])+'.bin',raw)],0 if answers[t['tcId']] else 1,'official-dkcheck-'+str(t['tcId']))
    raw,paths=first
    bad=bytearray(raw[3]);bad[2336]^=1
    both(['check',file('independent-stored-H-mismatch-dk2400.bin',bad)],1,'independent-stored-H-mismatch')
    bad=bytearray(raw[3]);bad[1152]=255;bad[1153]|=15
    assert (bad[1152]|((bad[1153]&15)<<8))==4095
    bad[2336:2368]=hashlib.sha3_256(bad[1152:2336]).digest()
    both(['check',file('independent-noncanonical-ek-recomputed-H-dk2400.bin',bad)],1,'independent-noncanonical-embedded-ek-with-correct-H')
    for i in (2,3):
        changed=bytearray(raw[i]);changed[0]^=1;alternate=list(paths);alternate[i]=file('changed-expected-'+str(i)+'.bin',changed)
        both(alternate,1,'wrong-expected-'+str(i))
    for i in range(4):
        alternate=list(paths);alternate[i]=file('short-'+str(i)+'.bin',raw[i][:-1]);both(alternate,2,'short-input-'+str(i))
    link=root/'symlink-d.bin';link.symlink_to(paths[0].name);both([link,*paths[1:]],2,'symlink-d-refused')
    assert len(cases)==88;pins()
except BaseException as ex:error=type(ex).__name__+': '+str(ex)[:300]
finally:
    for p in owned:
        if p.poll() is None:
            forced.append(p.pid);os.killpg(p.pid,signal.SIGTERM)
            try:p.wait(timeout=2)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=2)
    os.umask(oldmask)
pin_error=None
try:pins()
except BaseException as ex:pin_error=type(ex).__name__+': '+str(ex)[:200]
files=[]
for p in sorted(root.iterdir()):
    st=p.lstat();assert p.is_file() or p.is_symlink()
    files.append(dict(path=p.name,bytes=st.st_size,sha256=None if p.is_symlink() else sha(p),mode=oct(st.st_mode&0o777),uid=st.st_uid,inode=st.st_ino,mtime_ns=st.st_mtime_ns,link_target=os.readlink(p) if p.is_symlink() else None))
seal=root/'PRIVATE_INVENTORY.json';seal.write_text(json.dumps(dict(private=True,known_public_official_test_material_only=True,files=files),indent=2)+'\n')
duration=round(time.monotonic()-start,6)
completed=error is None and pin_error is None and not forced and len(cases)==88 and duration+used<=120
report=dict(format=stage['format'],completed=completed,duration_seconds=duration,original120_cumulative_seconds=round(duration+used,6),budget_seconds=120,attempts=1,error=error,pin_error=pin_error,results=results,cases=cases,forced_owned_processes=forced,owned_processes_stopped=all(p.poll() is not None for p in owned),controller_sha256=sha(Path(__file__)),stage_sha256=sha(stagep),actual_C_binary_sha256=sha(binary) if binary.exists() else None,actual_Rust_binary_sha256=sha(rust_binary) if rust_binary.exists() else None,private_inventory_sha256=sha(seal),private_files=len(files),Core_source=core['commitment'],known_public_standard_d_z_only=True,real_wallet_TLS_Native_key_reads=0,production_key_generation_calls=0,socket_calls=0,Native_Runtime_Node_calls=0,encap_decap_retests=0,full_FIPS203_KAT=False,production_random_source_qualification=False,constant_time_qualification=False,adopted_profile=False,independent_review=False,physical=False,whole_goal_completed=False,old_failures_retained=True)
out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('results','cases')}))
raise SystemExit(0 if completed else 1)
