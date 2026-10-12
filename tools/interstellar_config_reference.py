"""Original configured contact/endpoint predicates and constructor oracle, tests only."""
import ipaddress
import interstellar_mesh as mesh
import interstellar_spool_codec as spool_codec
require=mesh.require
integer=mesh.integer
hex32=mesh.hex32
safe_dir=mesh.safe_dir
SPOOL_ONEWAY=mesh.SPOOL_ONEWAY
MAX_CONTACTS=mesh.MAX_CONTACTS

def tcp_endpoint(host, port, listening=False):
    require(isinstance(host, str) and len(host) <= 15, 'TCP host must be a literal IPv4 address')
    address = ipaddress.IPv4Address(host)
    integer(port, 0 if listening else 1, 65535)
    require(not address.is_multicast and host != '255.255.255.255'
            and (listening or not address.is_unspecified), 'invalid TCP endpoint')
    return str(address), port


def contact_schema(contact):
    require(isinstance(contact,dict) and set(contact) in
            ({'peer','inbox','outbox'},{'peer','host','port'},
             {'peer','host','port','tls_cert_sha256'},
             {'peer','adapter','inbox'},{'peer','adapter','outbox'},
             {'peer','adapter','inbox','outbox'}),
            'invalid contact')
    if 'adapter' in contact:
        require(contact['adapter'] == spool_codec.FORMAT or
                (contact['adapter'] == SPOOL_ONEWAY and
                 set(contact) in ({'peer','adapter','inbox'}, {'peer','adapter','outbox'})),
                'unsupported spool adapter')
    return contact


def outgoing_contact(contact):
    return 'host' in contact or 'outbox' in contact


def incoming_contact(contact):
    return 'host' in contact or 'inbox' in contact


def contacts(self, config):
    contacts = config['contacts']
    require(isinstance(contacts, list) and len(contacts) <= MAX_CONTACTS, 'contact capacity reached')
    self.contacts = {}
    for contact in contacts:
        contact_schema(contact)
        peer = hex32(contact['peer'])
        require(peer != self.id and peer not in self.contacts, 'duplicate or self contact')
        if 'host' in contact:
            host, port = tcp_endpoint(contact['host'], contact['port'])
            self.contacts[peer] = {'host': host, 'port': port}
            if 'tls_cert_sha256' in contact:
                self.contacts[peer]['tls_cert_sha256'] = hex32(contact['tls_cert_sha256'])
        else:
            self.contacts[peer] = {k: safe_dir(contact[k]) for k in ('inbox', 'outbox') if k in contact}
            if contact.get('adapter') == spool_codec.FORMAT:
                self.contacts[peer]['adapter'] = spool_codec.FORMAT
            if 'inbox' in contact and 'outbox' in contact:
                require(self.contacts[peer]['inbox'] != self.contacts[peer]['outbox'], 'contact directions must differ')
    dirs = [p for contact in self.contacts.values() for name,p in contact.items() if name in ('inbox','outbox')]
    require(len(set(dirs)) == len(dirs), 'contact spools must be distinct')
    return self.contacts
