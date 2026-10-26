"""Robust-aggregation baselines from the literature, for comparison with our approach.

All of them need to *see each client's individual update*, so they cannot be combined with secure aggregation.
That incompatibility (robustness XOR privacy-from-the-server) is exactly the gap our design closes.

  median      coordinate-wise median                         (Yin et al., ICML 2018)
  trimmed     coordinate-wise trimmed mean, beta per side    (Yin et al., ICML 2018)
  krum        pick the update closest to its n-f-2 neighbours (Blanchard et al., NeurIPS 2017)
  multikrum   average of the n-f best Krum scores            (Blanchard et al., NeurIPS 2017)

`f` is the assumed number of Byzantine clients (we give the baselines the true number: an oracle advantage).
"""
import numpy as np


def _krum_scores(U, f):
    n = len(U)
    D = ((U[:, None, :] - U[None, :, :]) ** 2).sum(-1)
    m = max(1, n - f - 2)
    return np.array([np.sort(np.delete(D[i], i))[:m].sum() for i in range(n)])


def aggregate(name, U, f=1, beta=0.2):
    """U: (n_clients, d) array of updates. Returns a length-d 'mean-like' update."""
    n = len(U)
    if name == "mean":
        return U.mean(0)
    if name == "median":
        return np.median(U, axis=0)
    if name == "trimmed":
        k = int(beta * n)
        if n - 2 * k < 1:
            return U.mean(0)
        return np.sort(U, axis=0)[k:n - k].mean(0)
    if name == "krum":
        return U[int(np.argmin(_krum_scores(U, f)))]
    if name == "multikrum":
        keep = np.argsort(_krum_scores(U, f))[:max(1, n - f)]
        return U[keep].mean(0)
    raise ValueError(f"unknown aggregator {name}")
