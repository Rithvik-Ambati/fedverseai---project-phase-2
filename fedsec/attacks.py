"""Attack evaluation helpers.

Membership inference: loss-threshold attack (Yeom et al.). Scores are negative per-sample
loss; members are training records of all clients, non-members are held-out records of the
same silos. We report AUC and TPR at 1% / 5% FPR (low-FPR regime is what reviewers expect).
"""
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

from .model import per_sample_loss


def membership_inference(model, clients, seed=0):
    rng = np.random.RandomState(seed)
    Xm = np.vstack([c.Xtr for c in clients])
    ym = np.concatenate([c.ytr for c in clients])
    seen, Xn, yn = set(), [], []
    for c in clients:
        key = c.name.split("-")[0]
        if key not in seen:
            seen.add(key)
            Xn.append(c.Xte)
            yn.append(c.yte)
    Xn, yn = np.vstack(Xn), np.concatenate(yn)
    k = min(len(ym), len(yn))
    im, inn = rng.permutation(len(ym))[:k], rng.permutation(len(yn))[:k]
    score = -np.concatenate([per_sample_loss(model, Xm[im], ym[im]), per_sample_loss(model, Xn[inn], yn[inn])])
    lab = np.concatenate([np.ones(k), np.zeros(k)])
    fpr, tpr, _ = roc_curve(lab, score)
    return {"mia_auc": float(roc_auc_score(lab, score)),
            "mia_tpr@1%fpr": float(np.interp(0.01, fpr, tpr)),
            "mia_tpr@5%fpr": float(np.interp(0.05, fpr, tpr)),
            "mia_adv": float(np.max(tpr - fpr))}


def make_canaries(n_features, k, seed):
    """Out-of-distribution canary records: a model that memorises them reveals membership."""
    rng = np.random.RandomState(10_000 + seed)
    X = rng.normal(0, 3.0, size=(2 * k, n_features))
    y = rng.randint(0, 2, size=2 * k).astype(np.float32)
    return (X[:k], y[:k]), (X[k:], y[k:])


def canary_inference(model, ins, outs):
    """Loss-threshold test between canaries that were trained on (`ins`) and fresh ones (`outs`)."""
    score = -np.concatenate([per_sample_loss(model, *ins), per_sample_loss(model, *outs)])
    lab = np.concatenate([np.ones(len(ins[1])), np.zeros(len(outs[1]))])
    fpr, tpr, _ = roc_curve(lab, score)
    return {"canary_auc": float(roc_auc_score(lab, score)),
            "canary_tpr@5%fpr": float(np.interp(0.05, fpr, tpr)),
            "canary_tpr@10%fpr": float(np.interp(0.10, fpr, tpr))}
