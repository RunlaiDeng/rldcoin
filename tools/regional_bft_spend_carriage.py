"""Extra typed signature filter for already Native-retained Spend carriage.

This reconstructs the Native serde field order. It never checks a ledger,
actual input owners, conservation, maturity or freshness and grants no value,
proposal, vote or signing authority. Complete Native replay remains mandatory.
"""
import interstellar_mesh as mesh
import interstellar_transfer as wire


def amount(value):
    mesh.require(type(value) is str and 1<=len(value)<=39
                 and all('0'<=c<='9' for c in value)
                 and (len(value)==1 or value[0]!='0')
                 and int(value)<2**128,'Spend carriage amount encoding differs')
    return value


def payment(value):
    mesh.require(type(value) is dict and set(value)=={'owner','amount'},
                 'Spend carriage payment fields differ')
    return dict(owner=mesh.hex32(value['owner']),amount=amount(value['amount']))


def ordered_spend(command,currency,region):
    mesh.require(type(command) is dict and set(command)=={'Spend'},
                 'Spend carriage command differs')
    signed=command['Spend']
    mesh.require(type(signed) is dict and set(signed)=={'intent','approvals'},
                 'Spend carriage signed fields differ')
    intent=signed['intent'];approvals=signed['approvals']
    fields=('currency','region','inputs','outputs','fee','destination','remote','destination_fee','valid_through')
    mesh.require(type(intent) is dict and set(intent)==set(fields)
                 and intent['currency']==currency and intent['region']==region,
                 'Spend carriage intent domain/fields differ')
    inputs=intent['inputs'];outputs=intent['outputs'];height=intent['valid_through']
    mesh.require(type(inputs) is list and 1<=len(inputs)<=16
                 and type(outputs) is list and len(outputs)<=16
                 and type(height) is int and 0<=height<2**64,
                 'Spend carriage original typed bounds differ')
    inputs=[mesh.hex32(i) for i in inputs]
    mesh.require(inputs==sorted(set(inputs)),'Spend carriage input order differs')
    destination=intent['destination'];remote=intent['remote']
    mesh.require((destination is None)==(remote is None),'Spend carriage remote pair differs')
    ordered=dict(currency=mesh.hex32(currency),region=mesh.hex32(region),inputs=inputs,
                 outputs=[payment(p) for p in outputs],fee=amount(intent['fee']),
                 destination=None if destination is None else mesh.hex32(destination),
                 remote=None if remote is None else payment(remote),
                 destination_fee=amount(intent['destination_fee']),valid_through=height)
    mesh.require(type(approvals) is list and 1<=len(approvals)<=len(inputs),
                 'Spend carriage approval bound differs')
    data=b'RLD-REGIONAL-FIXTURE-V1:owner-intent\0'+wire.json.dumps(
        ordered,separators=(',',':'),ensure_ascii=False).encode()
    result=[]
    for approval in approvals:
        mesh.require(type(approval) is dict and set(approval)=={'key','signature'},
                     'Spend carriage approval fields differ')
        key=mesh.hex32(approval['key']);signature=approval['signature']
        mesh.require(type(signature) is str and len(signature)==128
                     and all(c in '0123456789abcdef' for c in signature),
                     'Spend carriage signature encoding differs')
        mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature),data)
        result.append(dict(key=key,signature=signature))
    keys=[a['key'] for a in result]
    mesh.require(keys==sorted(set(keys)),'Spend carriage approval order differs')
    return dict(Spend=dict(intent=ordered,approvals=result))
