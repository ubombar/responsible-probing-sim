class RPDemo:
    def __init__(self, num_dirs: int, impact_capacity: float, const: float = 1):
        self._p: dict[int, float] = {i: 1.0 for i in range(num_dirs)}
        self._A: dict[str, set[int]] = dict()
        self._Ar: dict[int, set[str]] = {i: set() for i in range(num_dirs)}
        self._C: float = impact_capacity
        self._const: float = const

    def add(self, directive_id: int, address: str) -> None:
        # if the directive_id is not known.
        if not directive_id in self._p:
            return

        # update the address if it is not seed before
        self._A[address] = self._A.get(address, set())
        self._Ar[directive_id] = self._Ar.get(directive_id, set())

        # populate the new addresses
        self._A[address].add(directive_id)
        self._Ar[directive_id].add(address)

        self._update_prob(directive_id)

    def remove(self, directive_id: int, address: str) -> None:
        # if the directive_id is not known.
        if not directive_id in self._p:
            return

        # update the address if it is not seed before
        self._A[address] = self._A.get(address, set())
        self._Ar[directive_id] = self._Ar.get(directive_id, set())

        # populate the new addresses
        self._A[address].remove(directive_id)
        self._Ar[directive_id].remove(address)

        self._update_prob(directive_id)

        # if there are non directives, remove address from map.
        if not self._A[address]:
            del self._A[address]

    def _update_prob(self, directive_id: int) -> None:
        candidates = {len(self._A.get(a, set())) for a in self._Ar[directive_id]}
        if not candidates:
            # no address seen, always issue
            self._p[directive_id] = 1.0
        else:
            # cap between 0 and 1.
            denom = max(candidates)
            self._p[directive_id] = min(max(self._const / denom, 0.0), 1.0)

    def get_probability(self, directive_id: int) -> float:
        return self._p.get(directive_id, 0.0)
