"""Classify and review public content before staging; never mutate Git.

This auxiliary detector does not replace human review of all new reachable blobs.
Normative versions, limits, public vector provenance and security explanations are
public. Internal experiment scheduling, outcomes and host/task metadata are local.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

KINDS = frozenset({'source', 'build-config', 'public-vector', 'developer-documentation',
                   'security-note', 'capability-boundary', 'acceptance-contract'})
DOC_KINDS = KINDS - {'source', 'build-config', 'public-vector'}
DOC_SUFFIXES = frozenset({'.md', '.rst', '.txt', '.html'})
LOCAL_PATHS = ('docs/operations/evidence/', 'docs/operations/fixtures/',
               'docs/operations/history/', 'tmp/', 'target/')
PROGRESS_FIELDS = frozenset({'duration_seconds', 'cumulative_seconds', 'previous_used_seconds',
                            'controller_sha256', 'stage_sha256', 'log_sha256',
                            'private_inventory_sha256', 'actual_process_peak_rss_bytes',
                            'forced_owned_processes', 'Native_Runtime_Node_calls'})
PROSE_PATTERNS = (
    r'\b(?:PASS|FAIL)\s*\d+(?:\.\d+)?\s*(?:秒|seconds?)',
    # A protocol name such as RLD-WIRE-V1 is not an experiment stage.
    r'(?<![\w-])V\d+\b[^\n]{0,180}(?:(?-i:\bPASS\b|\bFAIL\b)|累计\s*\d|耗时\s*\d|封存\s*\d)',
    r'\d+\.\d+\s*(?:秒|seconds?)',
    r'\b(?:controller_sha256|stage_sha256|private_inventory_sha256|duration_seconds|cumulative_seconds|actual_process_peak_rss_bytes)\b',
    r'/Users/[^\s`<>]+|/home/[^\s`<>]+|[A-Z]:\\Users\\',
    r'\b(?:thread|task|任务|线程)[^\n]{0,40}\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
    r'(?:下一(?:单一)?主线|下一(?:诊断|活动)假设|next\s+(?:stage\b|experiment\b|diagnostic\s+hypothesis))',
    r'(?:actual\s*binary|实际二进制|controller\s*(?:hash|SHA-?256))[^\n]{0,100}[0-9a-f]{64}\b',
    r'(?:source|binary|controller|源码|二进制)[^\n]{0,50}(?:hash|SHA-?256|哈希)[^\n]{0,70}[0-9a-f]{64}[^\n]{0,80}(?:PASS|通过|next\s*stage|进度)',
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def review_prose(text):
    for pattern in PROSE_PATTERNS:
        match = re.search(pattern, text, re.I)
        require(match is None, 'internal progress or host/task metadata in public prose: '
                + (match.group(0)[:120] if match else ''))


def json_progress(value):
    if isinstance(value, dict):
        require(not PROGRESS_FIELDS.intersection(value), 'internal run metadata in public JSON')
        require(value.get('private') is not True, 'private material marker')
        require(not {'private_key', 'private_key_hex', 'mnemonic', 'seed', 'secret_key',
                     'access_token'}.intersection(value), 'private material field')
        for child in value.values():
            json_progress(child)
    elif isinstance(value, list):
        for child in value:
            json_progress(child)
    elif isinstance(value, str):
        review_prose(value)


def review(root, selection):
    require(type(selection) is dict and set(selection) == {'files', 'content_classification'},
            'explicit files and content classification required')
    files, classification = selection['files'], selection['content_classification']
    require(type(files) is list and files and all(type(x) is str for x in files)
            and len(files) == len(set(files)) and type(classification) is dict
            and set(classification) == set(files), 'every exact public blob needs classification')
    reviewed = []
    for name in files:
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts
                and not name.startswith(LOCAL_PATHS) and path.name != 'AGENTS.md',
                'local/private path cannot be public')
        item = classification[name]
        require(type(item) is dict and set(item) == {'kind', 'purpose'}
                and item['kind'] in KINDS and type(item['purpose']) is str
                and 12 <= len(item['purpose']) <= 400, 'specific public purpose required')
        kind = item['kind']
        require(not (Path(root) / path).is_symlink()
                and Path(root).resolve() in (Path(root) / path).resolve().parents,
                'public input must remain in checkout and not be a symlink')
        raw = (Path(root) / path).read_bytes()
        text = raw.decode('utf-8')
        require(re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[ \t]*\r?\n(?:[A-Za-z0-9+/=]+[ \t]*\r?\n)+-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', text) is None, 'private key bytes')
        if path.suffix.lower() in DOC_SUFFIXES:
            require(kind in DOC_KINDS, 'prose cannot be classified as source/vector')
            review_prose(text)
        elif path.suffix == '.json':
            require(kind in {'public-vector', 'build-config'}, 'public JSON purpose differs')
            json_progress(json.loads(text))
        elif path.suffix in ('.py', '.rs', '.c', '.h', '.sh', '.js', '.mjs'):
            require(kind == 'source', 'code classification differs')
        else:
            require(kind in {'source', 'build-config'}, 'unclassified public artifact type')
        reviewed.append({'path': name, 'kind': kind, 'purpose': item['purpose'], 'bytes': len(raw)})
    return reviewed


def scan_tracked_documents(root):
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')
    errors = []
    for name in names:
        if Path(name).suffix.lower() in DOC_SUFFIXES:
            try:
                review_prose((Path(root) / name).read_text())
            except ValueError as exc:
                errors.append((name, str(exc)))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--scan-tracked-documents', action='store_true')
    parser.add_argument('--selection', type=Path)
    args = parser.parse_args()
    require(args.scan_tracked_documents != bool(args.selection), 'select exactly one review mode')
    if args.selection:
        review(args.root, json.loads(args.selection.read_text()))
    else:
        errors = scan_tracked_documents(args.root)
        for name, reason in errors:
            print(name + ': ' + reason)
        return 1 if errors else 0
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
