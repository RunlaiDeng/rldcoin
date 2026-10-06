#!/Users/galaxy/GitHub/rldcoin/tmp/rldcoin-goal-20261001-venv/bin/python -B
"""Exact future fixture --transport-python entry; no launch allocated today."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

PROJECT = Path('/Users/galaxy/GitHub/rldcoin')
BASE = PROJECT/'tmp/default-relay-20260930'
CONTRACT_PATH = BASE/'first_service_diagnostic_entry_contract_v20_20261006.json'
CONTRACT_SHA256 = 'f146ca0cc211647216ff04131500b61f52b0af74dd8f735fcd154514e6af88f3'
ALLOCATED = PROJECT/'docs/operations/evidence/regional-bft-warm-owner-entry-start-allocated-v32-20261006.json'
DRIVER_ARGV = str(PROJECT/'tools/regional-ledger') + '/../../tools/regional_contact_node.py'

FLAGS = ('--binary','--ledger','--authority','--currency','--interval',
         '--mesh-config','--bft-config','--listen')

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def safe(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and '.' not in path.parts,
            'diagnostic absolute normalized path')
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'diagnostic symlink refused')
    return path

def read_json(raw):
    def unique(pairs):
        result = {}
        for key,value in pairs:
            require(key not in result, 'diagnostic duplicate JSON field')
            result[key] = value
        return result
    return json.loads(raw,object_pairs_hook=unique)

def check_python_commitment(value):
    require(type(value) is dict and type(value.get('source_sha256')) is dict,
            'diagnostic Python source schema')
    sources = value['source_sha256']
    require(all(type(path) is str and type(digest) is str and len(digest) == 64
                and all(c in '0123456789abcdef' for c in digest)
                for path, digest in sources.items()), 'diagnostic source digest schema')
    python = {path: digest for path, digest in sources.items()
              if path.startswith('tools/') and path.endswith('.py')}
    require(len(python) == 192, 'diagnostic complete Python source set')
    raw = json.dumps(python, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=False, allow_nan=False).encode()
    require(hashlib.sha256(raw).hexdigest() == value.get('python_source_commitment'),
            'diagnostic Python source commitment differs from file map')


def load_contract():
    require(Path.cwd() == PROJECT and safe(CONTRACT_PATH) == CONTRACT_PATH,
            'explicit migrated diagnostic cwd')
    require(sha(CONTRACT_PATH) == CONTRACT_SHA256, 'diagnostic contract changed')
    value = read_json(CONTRACT_PATH.read_bytes())
    require(value['format'] == 'RLD-FIRST-SERVICE-DIAGNOSTIC-ENTRY-CONTRACT-V1'
            and value['project'] == str(PROJECT)
            and value['root'] == str(BASE/'native-bft-four-cli-service-first-service-diag-v32-private-20261006')
            and value['driver'] == str(PROJECT/'tools/regional_contact_node.py')
            and value['driver_argv'] == DRIVER_ARGV
            and value['full_fault_qualified'] is False and value['whole_goal_completed'] is False,
            'diagnostic source-only scope')
    for path, expected in value['source_sha256'].items():
        require(sha(safe(PROJECT/path)) == expected, 'diagnostic original source changed')
    check_python_commitment(value)
    require(sha(safe(value['binary'])) == value['actual_binary_sha256'], 'diagnostic actual binary changed')
    return value

def validate_invocation(argv, contract, decision):
    require(type(argv) is tuple and len(argv) == 17 and all(type(v) is str for v in argv)
            and argv[1::2] == FLAGS, 'diagnostic exact original Python driver argv')
    require(contract['driver_argv'] == DRIVER_ARGV and argv[0] == DRIVER_ARGV,
            'diagnostic exact Rust driver argv')
    safe(PROJECT/'tools/regional-ledger')
    require(safe(Path(argv[0]).resolve(strict=True)) == safe(contract['driver']),
            'diagnostic fixed Rust driver resolves to original source')
    root = safe(contract['root'])
    require(root == BASE/'native-bft-four-cli-service-first-service-diag-v32-private-20261006',
            'diagnostic old/foreign fixture root')
    require(type(decision) is dict and set(decision) == {'format','completed','root','budget_seconds',
            'attempts','native_starts','entry_sha256','contract_sha256','original_parameters','slots'}
            and decision['format'] == 'RLD-FIRST-SERVICE-ENTRY-ALLOCATED-V1'
            and decision['completed'] is True and decision['root'] == str(root)
            and type(decision['budget_seconds']) is int and decision['budget_seconds'] == 180
            and type(decision['attempts']) is int and decision['attempts'] == 1
            and type(decision['native_starts']) is int and decision['native_starts'] == 4
            and decision['entry_sha256'] == sha(Path(__file__))
            and decision['contract_sha256'] == CONTRACT_SHA256
            and json.dumps(decision['original_parameters'],sort_keys=True,separators=(',',':'),allow_nan=False)
                == json.dumps(contract['original_parameters'],sort_keys=True,separators=(',',':'),allow_nan=False),
            'diagnostic unallocated/changed original bounds')
    slots = decision['slots']
    require(type(slots) is list and len(slots) == 4 and all(type(v) is dict and set(v) == set(FLAGS)
            and all(type(x) is str for x in v.values()) for v in slots),
            'diagnostic exact four ordinary slots')
    require(len({v['--ledger'] for v in slots}) == len({v['--listen'] for v in slots}) == 4,
            'diagnostic copied/concurrent slot')
    values = dict(zip(argv[1::2],argv[2::2]))
    require(slots.count(values) == 1, 'diagnostic argv differs from allocated slot')
    index = slots.index(values)
    for i, value in enumerate(slots):
        require(safe(value['--binary']) == safe(contract['binary']) and value['--interval'] == '0.25',
                'diagnostic original binary/interval')
        for flag in ('--ledger','--mesh-config','--bft-config'):
            require(safe(value[flag]).is_relative_to(root), 'diagnostic external or old scope input')
        require(safe(value['--mesh-config']) == root/('component-mesh-config-'+str(i)+'.json')
                and safe(value['--bft-config']) == root/('component-bft-config-'+str(i)+'.json'),
                'diagnostic exact slot config')
        host, colon, port = value['--listen'].partition(':')
        require(host == '127.0.0.1' and colon == ':' and port.isdecimal() and 0 < int(port) < 65536,
                'diagnostic pinned loopback listener')
        for flag in ('--authority','--currency'):
            require(len(value[flag]) == 64 and all(c in '0123456789abcdef' for c in value[flag]),
                    'diagnostic original public binding')
    require(len({v['--currency'] for v in slots}) == len({v['--authority'] for v in slots}) == 1,
            'diagnostic currency/authority changed between replicas')
    require(not (root/'scope-terminal.json').exists()
            and not (root/'scope-final-cli-observations.json').exists(), 'diagnostic stopped fixture never reopen')
    return index, tuple(argv)

def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, 'diagnostic module loader')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    require(os.environ.get('RLD_GROUND_CONTACT_TRACE') == '1', 'explicit diagnostic opt-in required')
    contract = load_contract()
    require(ALLOCATED.is_file() and not ALLOCATED.is_symlink(), 'new diagnostic Native scope not allocated')
    require(ALLOCATED.stat().st_size <= 192*1024, 'diagnostic allocation byte capacity')
    decision = read_json(ALLOCATED.read_bytes())
    slot, original_argv = validate_invocation(tuple(sys.argv[1:]), contract, decision)
    mesh_root = Path(contract['root'])/'mesh'/str(slot)
    require(mesh_root.is_dir(), 'diagnostic fresh mesh setup required')
    # A permanent once-only observer receipt refuses copied/restarted telemetry.
    receipt = mesh_root/'first-service-observer-owner.json'
    descriptor = os.open(receipt, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(json.dumps(dict(process_id=os.getpid(),slot=slot,contract_sha256=CONTRACT_SHA256)).encode())
        stream.flush(); os.fsync(stream.fileno())
    sys.path.insert(0,str(PROJECT/'tools'))
    import interstellar_mesh as mesh
    import interstellar_tcp as tcp
    diagnostic = load_module(contract['observer'],'first_service_original_function_observer')
    ring = diagnostic.Ring(dict(process_id=os.getpid(),scope=contract['root'],slot=slot,
                                contract_sha256=CONTRACT_SHA256))
    observer = diagnostic.Observer(mesh,tcp,mesh_root,ring)
    observer.install()
    publisher = None
    old_argv = sys.argv
    try:
        publisher = diagnostic.Publisher(observer,mesh_root/'first-service-diag-status.json')
        sys.argv = list(original_argv)
        # Preserve script __main__, __file__, sys.argv and the original exception
        # handler; importing the driver as another module changes class identity.
        return runpy.run_path(original_argv[0],run_name='__main__')
    finally:
        sys.argv = old_argv
        if publisher is not None:
            observer.safe(publisher.close)
        observer.safe(observer.restore)

if __name__ == '__main__':
    try:
        main()
    except (OSError,ValueError,subprocess.TimeoutExpired) as error:
        raise SystemExit('regional contact node rejected: ' + str(error))
