"""Extra bounded timeout signature filter for carriage; no Native authority.

Only already Native-authenticated complete retained envelopes use this filter.
The ordered output matches the original fixed Ed25519 Native byte encoding.
No ledger, current-state, custody, quorum or signing decision is retained.
"""
import json

import interstellar_mesh as mesh

CONTEXT_FIELDS = ('currency', 'region', 'epoch', 'previous', 'parent_height',
                  'parent_block', 'parent_state')


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def approval(value, keys):
    mesh.require(type(value) is dict and set(value) == {'key', 'signature'}
                 and value['key'] in keys and type(value['signature']) is str
                 and len(value['signature']) == 128
                 and all(c in '0123456789abcdef' for c in value['signature']),
                 'timeout carriage approval shape')
    return dict(key=value['key'], signature=value['signature'])


def verify(approved, domain, value):
    data = ('RLD-REGIONAL-FIXTURE-V1:' + domain + '\0').encode() + encoded(value)
    mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(approved['key'])).verify(
        bytes.fromhex(approved['signature']), data)


def ordered_timeout_vote(timeout, context, keys, round_number):
    """Authenticate one bounded carriage hint; a vote is never a quorum."""
    mesh.require(type(context) is dict and set(context) == set(CONTEXT_FIELDS)
                 and type(context['parent_height']) is int
                 and 0 <= context['parent_height'] <= 64
                 and type(keys) is tuple and len(keys) == 4
                 and keys == tuple(sorted(set(keys)))
                 and type(round_number) is int and 0 <= round_number < 32,
                 'timeout carriage current context')
    current = {k: context[k] for k in CONTEXT_FIELDS}
    for key in keys:mesh.hex32(key)
    mesh.require(type(timeout) is dict
                 and set(timeout) == {'context', 'round', 'high', 'approval'}
                 and timeout['context'] == context
                 and type(timeout['round']) is int and timeout['round'] == round_number,
                 'timeout carriage mixed context or round')
    approved = approval(timeout['approval'], keys)
    high = timeout['high']
    if high is not None:
        mesh.require(type(high) is dict
                     and set(high) == {'context', 'round', 'value', 'phase', 'votes'}
                     and high['context'] == context
                     and type(high['round']) is int
                     and 0 <= high['round'] <= round_number
                     and high['phase'] == 'Prepare'
                     and type(high['votes']) is list and 3 <= len(high['votes']) <= 4,
                     'timeout carriage high Prepare shape')
        mesh.hex32(high['value'])
        mesh.require(high['value'] != '0' * 64, 'timeout carriage zero high value')
        votes, previous = [], None
        for vote in high['votes']:
            mesh.require(type(vote) is dict
                         and set(vote) == {'context', 'round', 'value', 'phase', 'approval'}
                         and vote['context'] == context
                         and type(vote['round']) is int and vote['round'] == high['round']
                         and vote['value'] == high['value'] and vote['phase'] == 'Prepare',
                         'timeout carriage mixed high Prepare')
            signer = approval(vote['approval'], keys)
            mesh.require(previous is None or previous < signer['key'],
                         'timeout carriage distinct high membership')
            previous = signer['key']
            verify(signer, 'bft-vote-v1',
                   [current, high['round'], high['value'], 'Prepare', signer['key']])
            votes.append(dict(context=current, round=high['round'], value=high['value'],
                              phase='Prepare', approval=signer))
        high = dict(context=current, round=high['round'], value=high['value'],
                    phase='Prepare', votes=votes)
    verify(approved, 'bft-timeout-v1', [current, round_number, high, approved['key']])
    return dict(context=current, round=round_number, high=high, approval=approved)


def ordered_timeout(certificate, context, keys, round_number):
    """Return exact ordered certificate and selected high value, or refuse.

    This finite nonrecursive shape has at most four timeouts, each with at most
    four Prepare votes. It grants a transport hint only; Rust independently
    validates every complete envelope, native prefix, lock and quorum.
    """
    mesh.require(type(context) is dict and set(context) == set(CONTEXT_FIELDS)
                 and type(context['parent_height']) is int
                 and 0 <= context['parent_height'] <= 64
                 and type(keys) is tuple and len(keys) == 4
                 and keys == tuple(sorted(set(keys)))
                 and type(round_number) is int and 1 <= round_number < 32,
                 'timeout carriage current context')
    current = {k: context[k] for k in CONTEXT_FIELDS}
    for key in keys:
        mesh.hex32(key)
    mesh.require(type(certificate) is dict
                 and set(certificate) == {'context', 'round', 'votes'}
                 and certificate['context'] == context
                 and type(certificate['round']) is int
                 and certificate['round'] == round_number - 1
                 and type(certificate['votes']) is list
                 and 3 <= len(certificate['votes']) <= 4,
                 'timeout carriage certificate shape')
    selected = None
    timeouts, last = [], None
    for timeout in certificate['votes']:
        ordered = ordered_timeout_vote(timeout, context, keys, certificate['round'])
        approved = ordered['approval']
        mesh.require(last is None or last < approved['key'],
                     'timeout carriage distinct ordered membership')
        last = approved['key']
        high = ordered['high']
        if high is not None:
            if selected is None or high['round'] > selected[0]:
                selected = (high['round'], high['value'])
            elif high['round'] == selected[0]:
                mesh.require(high['value'] == selected[1], 'timeout carriage equal-high conflict')
        timeouts.append(ordered)
    return (dict(context=current, round=certificate['round'], votes=timeouts),
            None if selected is None else selected[1])
