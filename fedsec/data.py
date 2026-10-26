"""UCI Heart Disease: four real hospital silos (Cleveland, Hungarian, Switzerland, VA).

The natural split is genuinely non-IID (different populations, different missingness),
which is a much better federated testbed than an artificial Dirichlet split of one hospital.
For scalability runs, silos are further divided into sub-clients (IID within a silo).
"""
import os
from dataclasses import dataclass

import numpy as np
import pandas as pd

COLS = ["age", "sex", "cp", "trestbps", "chol", "fbs", "restecg", "thalach",
        "exang", "oldpeak", "slope", "ca", "thal", "num"]
SILOS = ["cleveland", "hungarian", "switzerland", "va"]
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


@dataclass
class ClientData:
    cid: int
    name: str
    Xtr: np.ndarray
    ytr: np.ndarray
    Xte: np.ndarray
    yte: np.ndarray
    Xva: np.ndarray = None   # public validation set held by the server (only when val_frac > 0)
    yva: np.ndarray = None


def _load_silo(name):
    df = pd.read_csv(os.path.join(DATA_DIR, f"processed.{name}.data"), header=None, names=COLS, na_values="?")
    for c in ("chol", "trestbps"):          # 0 encodes "missing" in some silos
        df.loc[df[c] == 0, c] = np.nan
    df = df.apply(pd.to_numeric)
    y = (df["num"] > 0).astype(np.float32).values
    X = df.drop(columns="num")
    X = X.fillna(X.median()).fillna(0.0)    # silo-local imputation
    return X.values.astype(np.float64), y


def _covtype_silos(per_silo=5000):
    """UCI/sklearn Forest Covertype: the four wilderness areas are natural, strongly non-IID silos.
    Binary task: Lodgepole pine (class 2) vs the rest. A fixed sub-sample keeps experiments fast."""
    cache = os.path.join(DATA_DIR, "covtype_sample.npz")
    if not os.path.exists(cache):
        from sklearn.datasets import fetch_covtype
        d = fetch_covtype(data_home=os.path.join(DATA_DIR, "sk"))
        area = d.data[:, 10:14].argmax(1)
        X = np.hstack([d.data[:, :10], d.data[:, 14:]])
        y = (d.target == 2).astype(np.float32)
        rng = np.random.RandomState(0)
        keep = np.concatenate([rng.choice(np.where(area == a)[0], per_silo, replace=False) for a in range(4)])
        np.savez_compressed(cache, X=X[keep], y=y[keep], area=area[keep])
    z = np.load(cache)
    return {f"wild{a + 1}": (z["X"][z["area"] == a].astype(np.float64), z["y"][z["area"] == a]) for a in range(4)}


def load_silos(seed=0, test_frac=0.25, val_frac=0.0, dataset="heart"):
    rng = np.random.RandomState(seed)
    raw = {}
    source = _covtype_silos() if dataset == "covtype" else {s: _load_silo(s) for s in SILOS}
    for s, (X, y) in source.items():
        idx = rng.permutation(len(y))
        k = int(len(y) * (1 - test_frac))
        tr = idx[:k]
        nv = int(len(tr) * val_frac)          # carved from train, no extra RNG draws => val_frac=0 is unchanged
        va, tr = tr[:nv], tr[nv:]
        raw[s] = (X[tr], y[tr], X[idx[k:]], y[idx[k:]], X[va], y[va])
    # simulation shortcut: standardise with pooled train statistics
    pooled = np.vstack([v[0] for v in raw.values()])
    mu, sd = pooled.mean(0), pooled.std(0) + 1e-8
    return {s: ((a - mu) / sd, b, (c - mu) / sd, d, (e - mu) / sd, f) for s, (a, b, c, d, e, f) in raw.items()}


def make_clients(n_clients=4, seed=0, val_frac=0.0, dataset="heart"):
    """n_clients >= 4. Silos are split into sub-clients round-robin to reach n_clients."""
    assert n_clients >= len(SILOS)
    silos = load_silos(seed, val_frac=val_frac, dataset=dataset)
    counts = [n_clients // 4 + (1 if i < n_clients % 4 else 0) for i in range(4)]
    rng = np.random.RandomState(seed + 1)
    clients, cid = [], 0
    for (name, (Xtr, ytr, Xte, yte, Xva, yva)), k in zip(silos.items(), counts):
        idx = rng.permutation(len(ytr))
        for part in np.array_split(idx, k):
            clients.append(ClientData(cid, name if k == 1 else f"{name}-{cid}", Xtr[part], ytr[part],
                                      Xte, yte, Xva, yva))
            cid += 1
    return clients


def global_test(clients):
    seen, X, y = set(), [], []
    for c in clients:
        key = c.name.split("-")[0]
        if key not in seen:
            seen.add(key)
            X.append(c.Xte)
            y.append(c.yte)
    return np.vstack(X), np.concatenate(y)


def global_val(clients):
    seen, X, y = set(), [], []
    for c in clients:
        key = c.name.split("-")[0]
        if key not in seen and c.Xva is not None and len(c.yva):
            seen.add(key)
            X.append(c.Xva)
            y.append(c.yva)
    return np.vstack(X), np.concatenate(y)
