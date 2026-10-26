"""Small MLP (13 -> 16 -> 1) with flat-vector get/set, local SGD, evaluation."""
import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import roc_auc_score

torch.set_num_threads(1)


def build(n_in=13, hidden=16, seed=0):
    torch.manual_seed(seed)
    if hidden == 0:                      # logistic regression
        return nn.Sequential(nn.Linear(n_in, 1))
    return nn.Sequential(nn.Linear(n_in, hidden), nn.ReLU(), nn.Linear(hidden, 1))


def get_flat(model):
    return np.concatenate([p.detach().numpy().ravel() for p in model.parameters()]).astype(np.float64)


def set_flat(model, flat):
    i = 0
    for p in model.parameters():
        n = p.numel()
        p.data.copy_(torch.from_numpy(np.asarray(flat[i:i + n], dtype=np.float32)).view_as(p))
        i += n


def n_params(model):
    return sum(p.numel() for p in model.parameters())


def local_train(model, X, y, epochs, lr, batch=32, seed=0, flip=False):
    """Plain minibatch SGD. Returns nothing; model is updated in place."""
    g = torch.Generator().manual_seed(seed)
    Xt = torch.from_numpy(X.astype(np.float32))
    yt = torch.from_numpy(y.astype(np.float32))
    if flip:
        yt = 1.0 - yt
    opt = torch.optim.SGD(model.parameters(), lr=lr)
    lossf = nn.BCEWithLogitsLoss()
    for _ in range(epochs):
        perm = torch.randperm(len(yt), generator=g)
        for i in range(0, len(yt), batch):
            b = perm[i:i + batch]
            opt.zero_grad()
            lossf(model(Xt[b]).squeeze(1), yt[b]).backward()
            opt.step()


@torch.no_grad()
def predict_logits(model, X):
    return model(torch.from_numpy(X.astype(np.float32))).squeeze(1).numpy()


def per_sample_loss(model, X, y):
    z = predict_logits(model, X)
    return np.logaddexp(0, z) - y * z  # BCE with logits


def evaluate(model, X, y):
    z = predict_logits(model, X)
    acc = float(((z > 0) == (y > 0.5)).mean())
    try:
        auc = float(roc_auc_score(y, z))
    except ValueError:
        auc = float("nan")
    return {"acc": acc, "auc": auc, "loss": float(per_sample_loss(model, X, y).mean())}
