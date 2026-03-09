class RPDemo:
    def __init__(self, num_dirs: int, impact_capacity: float):
        self._B: dict[str, set[int]] = dict()
        self._R: dict[str, float] = dict()
        self._Br: dict[int, set[str]] = {i: set() for i in range(num_dirs)}
        self._p: dict[int, float] = {i: 1.0 for i in range(num_dirs)}
        self._C: float = impact_capacity

    def add(self, directive_id: int, address: str) -> None:
        """
        add takes two arguments, directive_id and address and adds the
        value to the B and Br matrix, updates the residuals.
        """
        # return if directive_id does not exist
        if not self.get_probability(directive_id):
            return

        # if the address or directive_id is already there then return
        if address in self._Br.get(directive_id, set()) or directive_id in self._B.get(
            address, set()
        ):
            return

        # populate the address if this is seen just now.
        self._B[address] = self._B.get(address, set())
        self._R[address] = self._R.get(address, self._C)

        # start mutating the state
        # add the impact to the current address.
        self._Br[directive_id].add(address)
        self._B[address].add(directive_id)

        # reduce the residual, if it is positive, we are done!
        if self._R[address] - self._p[directive_id] >= 0:
            self._R[address] -= self._p[directive_id]
            return

        # set the current residual to zero meaning we are at max capacity.
        self._R[address] = 0.0
        extra_residual = self._p[directive_id] - self._R[address]

        # get the directive_ids that has an impact on this address.
        current_directive_probs = {d: self._p[d] for d in self._B[address]}
        self._distribute_extra_residual(extra_residual, current_directive_probs)

    def remove(self, directive_id: int, address: str) -> None:
        """
        remove takes two arguments, directive_id and address and removes the
        value to the B and Br matrix, updates the residuals.
        """
        # return if directive_id does not exist
        if not self.get_probability(directive_id):
            return

        # if the address or directive_id is already there then return
        if address not in self._Br.get(
            directive_id, set()
        ) or directive_id not in self._B.get(address, set()):
            return

        # populate the address if this is seen just now.
        self._B[address] = self._B.get(address, set())
        self._R[address] = self._R.get(address, self._C)

        # start mutating the state
        # remove the impact to the current address.
        self._Br[directive_id].remove(address)
        self._B[address].remove(directive_id)

        # recover the residual, capped at C
        recovered = self._p[directive_id]
        self._R[address] = min(self._R[address] + self._p[directive_id], self._C)

        # redistribute recovered residual to other directives at this address
        if self._B[address]:
            current_directive_probs = {d: self._p[d] for d in self._B[address]}
            directive_limits = {
                d: min(self._R[a] for a in self._Br[d]) for d in current_directive_probs
            }
            self._redistribute_recovered_residual(
                recovered, current_directive_probs, directive_limits
            )

        # clean up if address is now empty
        if not self._B[address]:
            del self._B[address]
            del self._R[address]

    def get_probability(self, directive_id: int) -> float | None:
        """
        get_probability returns the probability of the provided directive_id.
        If the directive_id does not exist, then None is returned.
        """
        return self._p.get(directive_id, None)

    def _distribute_extra_residual(
        self,
        extra_residual: float,
        directive_probs: dict[int, float],
        tol: float = 1e-12,
    ) -> None:
        """
        Water-fill: reduce probabilities of directives to absorb extra_residual.
        In each round, share is split equally; directives that would go below 0
        are floored at 0 and drop out, their leftover recycled into the next round.
        """
        candidates = dict(directive_probs)  # shallow copy to mutate freely

        while extra_residual > tol and candidates:
            share = extra_residual / len(candidates)
            next_candidates = {}
            leftover = 0.0

            for d, prob in candidates.items():
                if share >= prob:
                    # This directive is exhausted — floor at 0
                    leftover += share - prob
                    self._p[d] = 0.0
                else:
                    self._p[d] -= share
                    next_candidates[d] = self._p[d]

            extra_residual = leftover
            candidates = next_candidates

    def _redistribute_recovered_residual(
        self,
        recovered: float,
        directive_probs: dict[int, float],
        directive_limits: dict[int, float],
        tol: float = 1e-12,
    ) -> None:
        """
        Water-fill in reverse: distribute recovered residual by increasing
        probabilities equally, capped at each directive's minimum residual limit.
        """
        candidates = dict(directive_probs)

        while recovered > tol and candidates:
            share = recovered / len(candidates)
            min_limit = min(directive_limits[d] for d in candidates)

            if share >= min_limit:
                next_candidates = {}
                for d in candidates:
                    if directive_limits[d] == min_limit:
                        self._p[d] += min_limit
                        recovered -= min_limit
                    else:
                        next_candidates[d] = candidates[d]
                        directive_limits[d] -= min_limit
                        self._p[d] += min_limit
                candidates = next_candidates
            else:
                for d in candidates:
                    self._p[d] += share
                recovered = 0.0
