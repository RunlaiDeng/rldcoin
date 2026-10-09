"""Durable bounded selected-input retry fence; no ledger or signing authority.

Store packet IDs only. Mesh custody must reconstruct exact complete bytes and
Native must authenticate them again. Empty metadata is not independent freshness
or protection against all-state rollback. Legacy progress without this sidecar
refuses unchanged; a fresh fixture is required.
"""
import interstellar_mesh as mesh
from regional_bft_node import private

FORMAT = 'RLD-BFT-INTAKE-PENDING-V1'
LIMIT = 4
MAX_BYTES = 8192


class IntakePending(ValueError):
    pass


class Pending:
    def __init__(self, path, binding, *, fresh):
        self.path, self.binding = path, binding
        self.failed = False
        if path.exists() or path.is_symlink():
            value = mesh.load(private(path), MAX_BYTES)
            mesh.require(type(value) is dict and set(value)=={'format','binding','packets'}
                         and value['format']==FORMAT and value['binding']==binding,
                         'BFT pending intake binding/version differs')
            packets = value['packets']
            mesh.require(type(packets) is list and len(packets)<=LIMIT
                         and all(type(ident) is str for ident in packets)
                         and packets==sorted(set(packets)), 'BFT pending intake capacity/order differs')
            for ident in packets:mesh.hex32(ident)
            self.packets = frozenset(packets)
        else:
            mesh.require(fresh, 'existing Origin contact progress lacks pending intake; use a fresh fixture')
            self.packets = frozenset()
            self.save(self.packets)

    def save(self, packets):
        self.failed = True
        mesh.require(len(packets)<=LIMIT, 'BFT pending intake capacity; retain selected evidence')
        for ident in packets:mesh.hex32(ident)
        private(self.path, missing=True)
        value=dict(format=FORMAT,binding=self.binding,packets=sorted(packets))
        mesh.require(len(mesh.evidence.canonical(value))<=MAX_BYTES,
                     'BFT pending intake bytes exceed bound; retain selected evidence')
        mesh.atomic(self.path,value)
        self.packets = frozenset(packets)
        self.failed = False

    def begin(self, packets):
        if self.failed:raise IntakePending('pending intake persistence unavailable; signing deferred')
        self.save(self.packets | frozenset(packets))

    def finish(self, packets):
        if self.failed:raise IntakePending('pending intake persistence unavailable; signing deferred')
        self.save(self.packets - frozenset(packets))

    def before_sign(self):
        if self.failed or self.packets:
            raise IntakePending('selected Native BFT intake remains pending; signing deferred')
