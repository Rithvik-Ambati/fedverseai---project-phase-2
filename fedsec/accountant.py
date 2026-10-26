"""Renyi-DP accountant for the (non-subsampled) Gaussian mechanism.

Each federated round releases  sum_i clip(x_i) + N(0, (z*C)^2)  where C is the clip norm
and z the *effective* noise multiplier. That is a Gaussian mechanism with L2 sensitivity C
(add/remove one client), which satisfies (alpha, alpha / (2 z^2))-RDP. RDP composes by
addition; conversion to (eps, delta) uses the tight bound of Balle et al. (2020).

The accountant is a pure function of the (public) per-round noise multipliers, so an
auditor can recompute any client's epsilon from the ledger.
"""
import math

ALPHAS = [1 + x / 10 for x in range(1, 100)] + list(range(12, 64)) + [80, 128, 256, 512]


def gaussian_rdp(z, alphas=ALPHAS):
    if z <= 0:
        return [math.inf] * len(alphas)
    return [a / (2.0 * z * z) for a in alphas]


def rdp_to_eps(rdp, delta, alphas=ALPHAS):
    best = math.inf
    for a, r in zip(alphas, rdp):
        if a <= 1 or math.isinf(r):
            continue
        eps = r + math.log1p(-1.0 / a) - (math.log(delta) + math.log(a)) / (a - 1)
        best = min(best, eps)
    return max(best, 0.0)


class RDPAccountant:
    def __init__(self, delta=1e-5):
        self.delta = delta
        self.rdp = [0.0] * len(ALPHAS)
        self.steps = 0

    def add(self, z):
        r = gaussian_rdp(z)
        self.rdp = [a + b for a, b in zip(self.rdp, r)]
        self.steps += 1

    def eps(self):
        if self.steps == 0:
            return 0.0
        return rdp_to_eps(self.rdp, self.delta)

    def projected(self, z):
        """Epsilon if one more round with multiplier z were added (does not mutate)."""
        r = gaussian_rdp(z)
        return rdp_to_eps([a + b for a, b in zip(self.rdp, r)], self.delta)


def eps_for(z, rounds, delta=1e-5):
    if z <= 0:
        return math.inf
    return rdp_to_eps([rounds * r for r in gaussian_rdp(z)], delta)


def noise_for_eps(target_eps, rounds, delta=1e-5):
    """Smallest z such that `rounds` Gaussian releases stay within target_eps."""
    lo, hi = 1e-2, 1e3
    for _ in range(80):
        mid = math.sqrt(lo * hi)
        if eps_for(mid, rounds, delta) > target_eps:
            lo = mid
        else:
            hi = mid
    return hi
