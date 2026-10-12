#!/usr/bin/env python3
"""Offline evidence carriage for adopted Earth cross-Zone transfers.

This application-layer transport has no value authority. Source and
destination nodes replay every delivered block, certificate and import.
Frames can travel through files, scheduled contacts, or a BPv7 payload.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen


FORMAT = 'RLD-INTERREGION-EVIDENCE-V1'
DOMAIN = (FORMAT + '\0').encode('ascii')
KINDS = {'source-sync', 'source-finality', 'finalized-import',
         'destination-sync', 'destination-receipt'}
CONTROL_KINDS = {'regional-bft'}
MAX_PAYLOAD = 3 * 1024 * 1024
MAX_FRAME = 4 * 1024 * 1024 + 4096
MAX_QUEUE_FILES = 4096
MAX_QUEUE_BYTES = 256 * 1024 * 1024
SOURCE_HEADER = b'RLD-EARTH-UNIFIED-SUCCESSOR-HEADER\0'
DEST_HEADER = b'RLD-EARTH-DESTINATION-POW-HEADER\0'
HEX = re.compile(r'[0-9a-f]{64}\Z')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def decode_json(data):
    return json.loads(data, object_pairs_hook=unique)


def hex32(value, name):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError(f'invalid {name}')
    return value


def read_file(path, limit):
    from interstellar_file_native import read_file as native
    return native(path, limit)


def ensure_dir(path):
    from interstellar_file_native import ensure_dir as native
    return native(path)


def write_new(path, data):
    from interstellar_file_native import write_new as native
    return native(path, data)


def write_same_or_new(path, data):
    from interstellar_file_native import write_same_or_new as native
    return native(path, data)


def make_frame(kind, source, destination, export, payload):
    from interstellar_frame_native import make_frame as native
    return native(kind, source, destination, export, payload)


def inspect_frame(data, source=None, destination=None):
    from interstellar_frame_native import inspect_frame as native
    return native(data, source, destination)


def queue_receive(root, data, source, destination):
    from interstellar_file_native import queue_receive as native
    return native(root, data, source, destination)


def queue_carry(root, message_id, output, source, destination):
    from interstellar_file_native import queue_carry as native
    return native(root, message_id, output, source, destination)


def loopback(value):
    parsed = urlparse(value)
    if (parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', '::1')
            or parsed.port is None or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('node origin must be explicit loopback HTTP')
    return value.rstrip('/')


def node_json(origin, path, value=None, limit=MAX_PAYLOAD):
    body = canonical(value) if value is not None else None
    request = Request(loopback(origin) + path, data=body,
                      method='POST' if body is not None else 'GET',
                      headers={'Content-Type': 'application/json'} if body is not None else {})
    with urlopen(request, timeout=20) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('node response exceeds bound')
    return decode_json(data)


def node_post_bytes(origin, path, body):
    request = Request(loopback(origin) + path, data=body, method='POST',
                      headers={'Content-Type': 'application/json'})
    with urlopen(request, timeout=20) as response:
        data = response.read(65537)
    if len(data) > 65536:
        raise ValueError('node acknowledgment exceeds bound')
    return decode_json(data)


def require_mature_receipt(receipt, checked):
    if (not isinstance(receipt, dict) or not isinstance(checked, dict)
            or checked.get('valid_on_selected_branches') is not True
            or checked.get('live_rld') is not True):
        raise ValueError('destination mirror did not verify receipt')
    try:
        included = int(receipt['block_height'])
        spendable = int(receipt['recipient_spendable_height'])
        confirmations = int(checked['confirmations'])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('invalid receipt maturity fields') from error
    if included < 0 or spendable < included + 6 or confirmations < 1:
        raise ValueError('invalid receipt maturity threshold')
    if included + confirmations - 1 < spendable:
        raise ValueError('destination import is not yet mature')
    return confirmations


def block_id(header, kind):
    if not isinstance(header, dict):
        raise ValueError('missing block header')
    def raw(name):
        return bytes.fromhex(hex32(header[name], name))
    def number(name, length):
        value = header[name]
        if not isinstance(value, (int, str)) or isinstance(value, bool):
            raise ValueError(f'invalid {name}')
        text = str(value)
        if not text.isascii() or not text.isdecimal() or (len(text) > 1 and text[0] == '0'):
            raise ValueError(f'noncanonical {name}')
        return int(text).to_bytes(length, 'big')
    domain = SOURCE_HEADER if kind == 'source-sync' else DEST_HEADER
    data = (domain + raw('chain_id') + raw('parent') + number('height', 16)
            + number('timestamp', 8) + raw('target') + raw('miner')
            + raw('commands_root') + raw('state_root') + number('nonce', 16))
    identifier = hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()
    if int(identifier, 16) > int(header['target'], 16):
        raise ValueError('block work is invalid')
    return identifier


def check_sync(page, kind, source, destination, anchor, common):
    expected = source if kind == 'source-sync' else destination
    pin_field = 'v1_tip' if kind == 'source-sync' else 'genesis'
    limit = 8 if kind == 'source-sync' else 2
    if (not isinstance(page, dict) or page.get('chain_id') != expected
            or page.get(pin_field) != anchor or page.get('common') != common
            or not isinstance(page.get('blocks'), list)
            or len(page['blocks']) > limit):
        raise ValueError('sync page identity or ancestry differs')
    parent = common
    for block in page['blocks']:
        header = block.get('header') if isinstance(block, dict) else None
        if not isinstance(header, dict) or header.get('chain_id') != expected or header.get('parent') != parent:
            raise ValueError('discontinuous sync page')
        parent = block_id(header, kind)
    hex32(page.get('tip'), 'sync tip')
    return parent


def capture_sync(args):
    kind = args.kind
    if kind not in ('source-sync', 'destination-sync'):
        raise ValueError('capture-sync requires a sync kind')
    source = hex32(args.source_chain, 'source chain')
    destination = hex32(args.destination_chain, 'destination chain')
    export = hex32(args.export_id, 'export ID')
    anchor = hex32(args.anchor, 'sync anchor')
    cursor = hex32(args.from_id, 'known tip')
    base = '/v1/earth' if kind == 'source-sync' else '/v1/earth-destination'
    status = node_json(args.origin, base + '/status', limit=65536)
    expected = source if kind == 'source-sync' else destination
    key = 'chain_id' if kind == 'source-sync' else 'destination_chain_id'
    if (status.get(key) != expected or status.get('storage_healthy') is not True
            or status.get('live_rld') is not True):
        raise ValueError('capture node identity or storage differs')
    if kind == 'destination-sync' and (not status.get('source_fresh') or status.get('halted')):
        raise ValueError('destination source view is unavailable')
    ensure_dir(args.output_dir)
    captured = []
    for _ in range(args.max_pages):
        page = node_json(args.origin, base + '/sync', {'locator': [cursor, anchor]})
        next_id = check_sync(page, kind, source, destination, anchor, cursor)
        if page['blocks']:
            data = make_frame(kind, source, destination, export, canonical(page))
            frame, _ = inspect_frame(data)
            write_same_or_new(args.output_dir / (frame['message_id'] + '.json'), data)
            captured.append(frame['message_id'])
        if next_id == page.get('tip'):
            return {'result': 'CAPTURED_UNVERIFIED_TRANSPORT', 'messages': captured,
                    'tip': next_id}
        if next_id == cursor:
            raise ValueError('sync page made no progress')
        cursor = next_id
    raise ValueError('sync page budget reached; carry captured frames and resume')


def apply_frame(args):
    data = read_file(args.input, MAX_FRAME)
    frame, payload = inspect_frame(data, args.source_chain, args.destination_chain)
    value = decode_json(payload)
    if not isinstance(value, dict):
        raise ValueError('evidence payload must be a JSON object')
    kind = frame['kind']
    source = frame['source_chain_id']
    destination = frame['destination_chain_id']
    export = frame['export_id']
    if kind in ('source-sync', 'destination-sync'):
        origin = args.source_origin if kind == 'source-sync' else args.destination_origin
        if not origin:
            raise ValueError('missing local node origin')
        anchor = hex32(args.anchor, 'sync anchor')
        common = hex32(value.get('common'), 'sync common')
        check_sync(value, kind, source, destination, anchor, common)
        base = '/v1/earth' if kind == 'source-sync' else '/v1/earth-destination'
        status = node_json(origin, base + '/status', limit=65536)
        key = 'chain_id' if kind == 'source-sync' else 'destination_chain_id'
        if (status.get(key) != (source if kind == 'source-sync' else destination)
                or status.get('storage_healthy') is not True
                or status.get('live_rld') is not True):
            raise ValueError('local adopted node identity or storage differs')
        for block in value['blocks']:
            node_post_bytes(origin, base + '/blocks', canonical(block))
        return {'result': 'NODE_VALIDATED_SYNC', 'message_id': frame['message_id'],
                'blocks': len(value['blocks'])}
    if kind == 'source-finality':
        statement = value.get('statement')
        if not isinstance(statement, dict) or statement.get('source_chain_id') != source:
            raise ValueError('certificate source differs')
        response = node_post_bytes(args.source_origin, '/v1/earth/finality', payload)
        if response.get('finalized') is not True:
            raise ValueError('source node did not install finality')
        return {'result': 'SOURCE_NODE_INSTALLED_FINALITY', 'message_id': frame['message_id']}
    if kind == 'finalized-import':
        item = value.get('FinalizedImport')
        if not isinstance(item, dict):
            raise ValueError('missing finalized import')
        bundle = item.get('bundle')
        cert = item.get('certificate')
        if not isinstance(bundle, dict) or not isinstance(cert, dict) or not isinstance(cert.get('statement'), dict):
            raise ValueError('invalid finalized import')
        if (bundle.get('source_chain_id') != source
                or bundle.get('destination_chain_id') != destination
                or bundle.get('export_id') != export
                or bundle.get('source_checkpoint') != cert.get('statement', {}).get('block')):
            raise ValueError('import payload differs from frame route')
        response = node_post_bytes(args.destination_origin, '/v1/earth-destination/commands', payload)
        if response.get('live_rld') is not True:
            raise ValueError('destination node did not accept adopted command')
        return {'result': 'DESTINATION_COMMAND_SUBMITTED', 'message_id': frame['message_id'],
                'included': response.get('candidate_included', False)}
    if kind == 'destination-receipt':
        bundle, receipt = value.get('bundle'), value.get('receipt')
        if not isinstance(bundle, dict) or not isinstance(receipt, dict):
            raise ValueError('invalid destination receipt')
        if (bundle.get('source_chain_id') != source
                or bundle.get('destination_chain_id') != destination
                or bundle.get('export_id') != export
                or receipt.get('export_id') != export):
            raise ValueError('receipt route differs')
        response = node_json(args.destination_origin, '/v1/earth-destination/verify-receipt', value)
        confirmations = require_mature_receipt(receipt, response)
        return {'result': 'LOCALLY_VERIFIED_DESTINATION_RECEIPT',
                'message_id': frame['message_id'], 'confirmations': confirmations}
    raise ValueError('unsupported frame kind')


def capture_receipt(args):
    command = decode_json(read_file(args.import_command, MAX_PAYLOAD))
    if not isinstance(command, dict) or not isinstance(command.get('FinalizedImport'), dict):
        raise ValueError('missing finalized import command')
    bundle = command['FinalizedImport'].get('bundle')
    if not isinstance(bundle, dict):
        raise ValueError('missing import proof bundle')
    if (bundle.get('source_chain_id') != args.source_chain
            or bundle.get('destination_chain_id') != args.destination_chain
            or bundle.get('export_id') != args.export_id):
        raise ValueError('import command differs from route')
    policy = decode_json(read_file(args.policy, 16384))
    if not isinstance(policy, dict) or policy.get('destination_chain_id') != args.destination_chain:
        raise ValueError('receipt policy destination differs')
    receipt = node_json(args.destination_origin, '/v1/earth-destination/receipts',
                        {'bundle': bundle, 'policy': policy}, limit=65536)
    if (not isinstance(receipt, dict) or receipt.get('source_chain_id') != args.source_chain
            or receipt.get('destination_chain_id') != args.destination_chain
            or receipt.get('export_id') != args.export_id
            or receipt.get('destination_genesis') != policy.get('accepted_genesis')):
        raise ValueError('destination receipt identity differs')
    value = {'bundle': bundle, 'policy': policy, 'receipt': receipt}
    checked = node_json(args.destination_origin, '/v1/earth-destination/verify-receipt', value)
    require_mature_receipt(receipt, checked)
    data = make_frame('destination-receipt', args.source_chain, args.destination_chain,
                      args.export_id, canonical(value))
    write_new(args.output, data)
    return {'result': 'CAPTURED_DESTINATION_RECEIPT_NOT_REMOTE_VERIFIED',
            'message_id': inspect_frame(data)[0]['message_id']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    def route(command):
        command.add_argument('--source-chain', required=True)
        command.add_argument('--destination-chain', required=True)
        command.add_argument('--export-id', required=True)
    pack = commands.add_parser('pack', help='wrap exact evidence bytes without granting authority')
    route(pack)
    pack.add_argument('--kind', required=True, choices=sorted(KINDS))
    pack.add_argument('--payload-file', required=True, type=Path)
    pack.add_argument('--output', required=True, type=Path)
    receive = commands.add_parser('receive', help='durably retain an exact frame')
    receive.add_argument('--source-chain', required=True)
    receive.add_argument('--destination-chain', required=True)
    receive.add_argument('--queue', required=True, type=Path)
    receive.add_argument('--input', required=True, type=Path)
    carry = commands.add_parser('carry', help='copy retained bytes to a contact medium')
    carry.add_argument('--source-chain', required=True)
    carry.add_argument('--destination-chain', required=True)
    carry.add_argument('--queue', required=True, type=Path)
    carry.add_argument('--message-id', required=True)
    carry.add_argument('--output', required=True, type=Path)
    sync = commands.add_parser('capture-sync', help='capture bounded selected-chain sync pages')
    route(sync)
    sync.add_argument('--kind', required=True, choices=['source-sync', 'destination-sync'])
    sync.add_argument('--origin', required=True)
    sync.add_argument('--anchor', required=True)
    sync.add_argument('--from-id', required=True)
    sync.add_argument('--max-pages', type=int, default=256)
    sync.add_argument('--output-dir', required=True, type=Path)
    apply = commands.add_parser('apply', help='submit evidence to local replaying nodes')
    apply.add_argument('--source-chain', required=True)
    apply.add_argument('--destination-chain', required=True)
    apply.add_argument('--input', required=True, type=Path)
    apply.add_argument('--source-origin')
    apply.add_argument('--destination-origin')
    apply.add_argument('--anchor', help='source v1 tip or destination genesis for sync frames')
    receipt = commands.add_parser('capture-receipt', help='capture a mature destination inclusion receipt')
    route(receipt)
    receipt.add_argument('--destination-origin', required=True)
    receipt.add_argument('--import-command', required=True, type=Path)
    receipt.add_argument('--policy', required=True, type=Path)
    receipt.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if hasattr(args, 'source_chain'):
        hex32(args.source_chain, 'source chain')
        hex32(args.destination_chain, 'destination chain')
    if hasattr(args, 'export_id'):
        hex32(args.export_id, 'export ID')
    if hasattr(args, 'max_pages') and not 1 <= args.max_pages <= 256:
        parser.error('max-pages must be between 1 and 256')
    try:
        if args.command == 'pack':
            data = make_frame(args.kind, args.source_chain, args.destination_chain,
                              args.export_id, read_file(args.payload_file, MAX_PAYLOAD))
            write_new(args.output, data)
            result = {'result': 'PACKED_UNVERIFIED_TRANSPORT',
                      'message_id': inspect_frame(data)[0]['message_id']}
        elif args.command == 'receive':
            message_id, new = queue_receive(args.queue, read_file(args.input, MAX_FRAME),
                                            args.source_chain, args.destination_chain)
            result = {'result': 'DURABLY_RECEIVED_NO_VALUE_AUTHORITY',
                      'message_id': message_id, 'new': new}
        elif args.command == 'carry':
            frame = queue_carry(args.queue, args.message_id, args.output,
                                args.source_chain, args.destination_chain)
            result = {'result': 'CARRIED_EXACT_BYTES', 'message_id': frame['message_id']}
        elif args.command == 'capture-sync':
            result = capture_sync(args)
        elif args.command == 'apply':
            result = apply_frame(args)
        else:
            result = capture_receipt(args)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, OverflowError, TypeError) as error:
        parser.exit(1, f'{type(error).__name__}: {error}\n')


if __name__ == '__main__':
    main()
