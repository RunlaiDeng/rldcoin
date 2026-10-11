"""Former Python crypto for independent tests and explicit fixture SDK keys only.

Normal Node identities use the native file signer. This is never a native-error
fallback and supplies no ledger, custody or finality authority.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import interstellar_transfer as wire

def sign_reference(key,kind,body):
    public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
    return dict(body=body,public_key=public,
        signature=key.sign(('RLD-CONTACT-MESH-V3\0'+kind+'\0').encode()+wire.canonical(body)).hex())

def verify_reference(value,kind,network):
    import interstellar_mesh as mesh
    mesh.require(type(value) is dict and set(value)=={'body','public_key','signature'},'invalid signed object')
    body=value['body'];mesh.require(type(body) is dict and body.get('network')==network
        and body.get('format')==mesh.VERSION,'wrong network or version')
    public=mesh.hex32(value['public_key'])
    mesh.require(type(value['signature']) is str and len(value['signature'])==128
        and all(c in '0123456789abcdef' for c in value['signature']),'invalid signature encoding')
    try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes.fromhex(value['signature']),
        (mesh.VERSION+'\0'+kind+'\0').encode()+wire.canonical(body))
    except InvalidSignature as error:raise ValueError('invalid signature') from error
    mesh.require(body.get('node_id')==mesh.node_id(public),'node identity mismatch');return body
