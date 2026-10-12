"""Original candidate BFS for independent explicit tests; no ledger authority."""
from interstellar_mesh import outgoing_contact

def route(self, destination, excluded=(), first_hop=None):
        if destination == self.id:
            return [self.id]
        frontier, seen = [[self.id]], set(excluded) | {self.id}
        while frontier:
            path = frontier.pop(0)
            advert = self.state['adverts'].get(path[-1])
            if not advert:
                continue
            for peer in advert['body']['neighbors']:
                if peer in seen or (len(path) == 1 and
                        (peer not in self.contacts or not outgoing_contact(self.contacts[peer])
                         or (first_hop is not None and peer != first_hop))):
                    continue
                if peer == destination:
                    return path + [peer]
                seen.add(peer)
                frontier.append(path + [peer])
        return None
