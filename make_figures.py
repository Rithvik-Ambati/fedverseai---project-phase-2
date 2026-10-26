"""Render slide-ready figures from results/*.csv  ->  results/figures/*.png

    python make_figures.py
"""
import os, warnings

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
R = "results"
OUT = os.environ.get("FEDSEC_FIG_DIR", os.path.join(R, "figures"))
DPI = int(os.environ.get("FEDSEC_FIG_DPI", "200"))
PDF = os.environ.get("FEDSEC_FIG_PDF") == "1"
os.makedirs(OUT, exist_ok=True)

NAVY, TEAL, ORANGE, RED, GREY, GREEN = "#1f2a44", "#1b998b", "#f28f3b", "#d1495b", "#8d99ae", "#2e933c"
plt.rcParams.update({"font.size": 13, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                     "grid.alpha": 0.25, "figure.dpi": 100, "savefig.dpi": 200, "axes.titleweight": "bold",
                     "font.family": "DejaVu Sans"})


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name), bbox_inches="tight", facecolor="white", dpi=DPI)
    if PDF:
        fig.savefig(os.path.join(OUT, name.rsplit(".", 1)[0] + ".pdf"), bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("  ", name)


def band(ax, x, g, color, label, marker="o"):
    m, s = g.mean(), g.std().fillna(0)
    ax.plot(x, m, marker=marker, color=color, label=label, lw=2.5, ms=7)
    ax.fill_between(x, m - s, m + s, color=color, alpha=0.15)


# ------------------------------------------------------------------ 1. privacy vs utility
d = pd.read_csv(f"{R}/privacy_utility.csv")
fig, (a, b) = plt.subplots(1, 2, figsize=(12, 4.6))
base = d[(d.setting == "FedAvg (no DP)")].acc.mean()
for mode, col, lab in (("local DP", GREY, "Local DP (each client adds full noise)"),
                       ("distributed DP", TEAL, "Distributed DP + SecAgg (ours)")):
    g = d[(d.setting == mode) & (d.rounds == 5)].groupby("eps_target").acc
    xs = sorted(d[(d.setting == mode) & (d.rounds == 5)].eps_target.unique())
    band(a, xs, g, col, lab)
a.axhline(base, ls="--", color=NAVY, lw=1.6)
a.text(1.05, base + 0.008, f"FedAvg, no privacy ({base:.2f})", color=NAVY, fontsize=11)
a.set_xscale("log", base=2)
a.set_xticks([1, 2, 4, 8, 16, 32]); a.set_xticklabels(["1", "2", "4", "8", "16", "32"])
a.set_xlabel("privacy budget ε  (smaller = more private)"); a.set_ylabel("test accuracy")
a.set_title("Privacy vs accuracy"); a.legend(loc="lower right", fontsize=10.5); a.set_ylim(0.45, 0.87)
for mode, col, lab in (("local DP", GREY, "Local DP"), ("distributed DP", TEAL, "Distributed DP (ours)")):
    s = d[(d.setting == mode) & (d.eps_target == 8)]
    g = s.groupby("rounds").acc
    band(b, sorted(s.rounds.unique()), g, col, lab, marker="s")
b.set_xscale("log"); b.set_xticks([3, 5, 10, 20, 40]); b.set_xticklabels(["3", "5", "10", "20", "40"])
b.set_xlabel("communication rounds (ε fixed at 8)"); b.set_ylabel("test accuracy")
b.set_title("Fewer rounds are better under DP"); b.legend(loc="lower left", fontsize=10.5); b.set_ylim(0.45, 0.87)
save(fig, "fig1_privacy_utility.png")

# ------------------------------------------------------------------ 2. membership inference
m = pd.read_csv(f"{R}/membership.csv")
order = [np.inf, 256, 64, 16, 4]
g = m.groupby("eps_target")
auc_m = [g.canary_auc.mean()[e] for e in order]
auc_s = [g.canary_auc.std()[e] for e in order]
acc_m = [g.acc.mean()[e] for e in order]
labels = ["no DP", "ε=256", "ε=64", "ε=16", "ε=4"]
fig, ax = plt.subplots(figsize=(8.5, 4.8))
bars = ax.bar(labels, auc_m, yerr=auc_s, color=[RED, ORANGE, "#e9c46a", TEAL, TEAL], capsize=5, width=0.6)
ax.axhline(0.5, color=NAVY, ls="--", lw=1.6)
ax.text(4.45, 0.512, "random guessing", ha="right", color=NAVY, fontsize=11)
for r_, v, a_ in zip(bars, auc_m, acc_m):
    ax.text(r_.get_x() + r_.get_width() / 2, 0.37, f"model acc\n{a_:.2f}", ha="center", fontsize=10, color="white",
            fontweight="bold")
ax.set_ylim(0.35, 0.78); ax.set_ylabel("attacker's AUC (higher = more leakage)")
ax.set_title("Membership inference on planted records")
save(fig, "fig2_membership.png")

# ------------------------------------------------------------------ 3. attacks
a_ = pd.read_csv(f"{R}/attacks.csv")
scen = [("poison: sign-flip x10", "Poisoning\n(sign-flip ×10)"),
        ("stealth poison (forged input)", "Stealth poison\n(forged input)"),
        ("server reverses aggregate", "Server reverses\naggregate"),
        ("server drops a client", "Server drops\na hospital"),
        ("missing DP noise (under-report)", "Client skips\nDP noise"),
        ("over-budget declaration", "Dodges privacy\nbudget"),
        ("poison: label-flip (2 clients)", "Label-flip\n(within bound)")]
und, ours = "FedAvg+DP+SecAgg (no ledger)", "ours, audit 25%"
clean = a_[(a_.attack == "none") & (a_.defence == und)].acc.mean()
x = np.arange(len(scen)); w = 0.38
fig, ax = plt.subplots(figsize=(13, 5.2))
mu = [a_[(a_.attack == s) & (a_.defence == und)].acc.mean() for s, _ in scen]
mo = [a_[(a_.attack == s) & (a_.defence == ours)].acc.mean() for s, _ in scen]
su = [a_[(a_.attack == s) & (a_.defence == und)].acc.std() for s, _ in scen]
so = [a_[(a_.attack == s) & (a_.defence == ours)].acc.std() for s, _ in scen]
ax.bar(x - w / 2, mu, w, yerr=su, color=RED, capsize=4, label="undefended (DP + SecAgg only)")
ax.bar(x + w / 2, mo, w, yerr=so, color=TEAL, capsize=4, label="full system (ledger + audits)")
ax.axhline(clean, color=NAVY, ls="--", lw=1.5)
ax.text(-0.45, clean + 0.012, f"clean run {clean:.2f}", ha="left", color=NAVY, fontsize=10.5)
for i, (s_, _) in enumerate(scen):
    det = a_[(a_.attack == s_) & (a_.defence == ours)].detected.mean()
    txt = "✔ detected" if det >= 0.99 else ("✘ not detected" if det <= 0.01 else f"detected {det:.0%}")
    ax.text(i, 0.94, txt, ha="center", fontsize=11.5, fontweight="bold", color=GREEN if det >= 0.99 else RED)
ax.set_xticks(x); ax.set_xticklabels([l for _, l in scen], fontsize=11)
ax.set_ylim(0, 1.0); ax.set_ylabel("final test accuracy")
ax.set_title("Attacks: undefended vs full system", pad=34)
ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), fontsize=11, ncol=2, frameon=False)
save(fig, "fig3_attacks.png")

# ------------------------------------------------------------------ 4. audit trade-off
t = pd.read_csv(f"{R}/audit_tradeoff.csv")
fig, (p, q, r) = plt.subplots(1, 3, figsize=(15, 4.6))
rates = sorted(t.audit_rate.unique())
nz = t[t.attacker == "no DP noise"]
for mode, col, lab in (("seeded", TEAL, "seeded-noise audit (ours)"), ("statistical", GREY, "statistical audit")):
    g = nz[nz.audit_mode == mode].groupby("audit_rate").caught.mean()
    p.plot(rates, [g[x_] for x_ in rates], marker="o", color=col, lw=2.5, ms=7, label=lab)
p.set_xlabel("audit rate"); p.set_ylabel("fraction of runs where cheater is banned"); p.set_ylim(-0.05, 1.1)
p.set_title("Catching a client that skips noise"); p.legend(fontsize=10, loc="center right")
sf = t[(t.attacker == "sign-flip x10") & (t.audit_mode == "seeded")]
band(q, rates, sf.groupby("audit_rate").acc, TEAL, "accuracy with a poisoner present")
q.axhline(0.8, color=NAVY, ls="--", lw=1.3); q.text(0.02, 0.82, "clean run ≈0.80", color=NAVY, fontsize=10)
q.set_xlabel("audit rate"); q.set_ylabel("final accuracy"); q.set_ylim(0.2, 0.9)
q.set_title("Poisoner vs audit rate")
ex = sf.groupby("audit_rate").honest_exposure.mean()
r.bar([f"{x_:.0%}" for x_ in rates], [ex[x_] for x_ in rates], color=ORANGE, width=0.6)
r.set_xlabel("audit rate"); r.set_ylabel("share of rounds an honest client is opened")
r.set_title("The price: privacy exposure"); r.set_ylim(0, 1.1)
save(fig, "fig4_audit_tradeoff.png")

# ------------------------------------------------------------------ 5. overhead + dropout
o = pd.read_csv(f"{R}/overhead.csv")
order_v = ["FedAvg", "+DP", "+DP+SecAgg", "+DP+SecAgg+Ledger (full)"]
cols = [GREY, "#e9c46a", ORANGE, TEAL]
fig, ax = plt.subplots(1, 3, figsize=(15, 4.4))
for v, c in zip(order_v, cols):
    s = o[o.variant == v].sort_values("clients")
    ax[0].plot(s.clients, s.bytes_per_client_round / 1024, marker="o", color=c, lw=2.5, label=v)
    ax[1].plot(s.clients, s.time_per_round_s, marker="o", color=c, lw=2.5, label=v)
s = o[o.variant == order_v[-1]].sort_values("clients")
ax[2].plot(s.clients, s.gas_per_round / 1e6, marker="o", color=TEAL, lw=2.5)
ax[0].set_ylabel("KB per client per round"); ax[0].set_title("Communication"); ax[0].legend(fontsize=9)
ax[1].set_ylabel("seconds per round"); ax[1].set_title("Compute (training dominates)"); ax[1].set_ylim(0, 0.6)
ax[2].set_ylabel("million gas per round (estimate)"); ax[2].set_title("Ledger cost")
for a in ax:
    a.set_xlabel("number of clients"); a.set_xticks([4, 8, 16, 32])
save(fig, "fig5_overhead.png")

dr = pd.read_csv(f"{R}/dropout.csv")
g = dr.groupby("dropout")
fig, (a1, a2) = plt.subplots(1, 2, figsize=(11, 4.2))
a1.plot(g.accepted_rounds.mean().index * 100, g.accepted_rounds.mean(), marker="o", color=TEAL, lw=2.5)
a1.set_xlabel("client dropout (%)"); a1.set_ylabel("rounds completed (of 10)"); a1.set_ylim(0, 11)
a1.set_title("Secure aggregation survives dropouts")
a2.plot(g.eps_max.mean().index * 100, g.eps_max.mean(), marker="o", color=ORANGE, lw=2.5)
a2.axhline(8, color=NAVY, ls="--", lw=1.3); a2.text(1, 8.05, "planned ε = 8", color=NAVY, fontsize=10)
a2.set_xlabel("client dropout (%)"); a2.set_ylabel("ε actually spent"); a2.set_title("Ledger charges the real privacy cost")
save(fig, "fig6_dropout.png")

# ------------------------------------------------------------------ 0. architecture / round flow
fig, ax = plt.subplots(figsize=(14, 6.2))
ax.set_xlim(0, 14); ax.set_ylim(0, 6.2); ax.axis("off")


def box(x, y, w, h, title, sub, color, tc="white"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.04,rounding_size=0.12", fc=color, ec="none"))
    ax.text(x + w / 2, y + h * 0.66, title, ha="center", va="center", color=tc, fontsize=12.5, fontweight="bold")
    ax.text(x + w / 2, y + h * 0.28, sub, ha="center", va="center", color=tc, fontsize=9.6)


def arrow(x1, y1, x2, y2, c=NAVY):
    ax.annotate("", (x2, y2), (x1, y1), arrowprops=dict(arrowstyle="-|>", color=c, lw=2))


ax.text(0.1, 5.85, "Hospitals (private data never leaves)", fontsize=12, fontweight="bold", color=NAVY)
box(0.1, 4.1, 2.6, 1.5, "1  Train locally", "own patients only", NAVY)
box(3.1, 4.1, 2.6, 1.5, "2  Clip + DP noise", "noise from committed seed", NAVY)
box(6.1, 4.1, 2.6, 1.5, "3  Commit", "Pedersen commitment\nto the update", ORANGE)
box(9.1, 4.1, 2.6, 1.5, "4  Mask", "pairwise masks cancel\nonly in the sum", NAVY)
for xa in (2.7, 5.7, 8.7):
    arrow(xa, 4.85, xa + 0.4, 4.85)
ax.text(12.2, 5.85, "Server (untrusted)", fontsize=12, fontweight="bold", color=RED)
box(12.0, 4.1, 1.9, 1.5, "5  Sum", "sees masked\nvectors only", RED)
arrow(11.7, 4.85, 12.0, 4.85)

ax.text(0.1, 3.35, "Verification (anyone)", fontsize=12, fontweight="bold", color=TEAL)
box(0.1, 1.6, 3.5, 1.5, "6  Check the sum", "Π commitments = Com(aggregate)\n→ no drop / swap / forgery", TEAL)
box(4.0, 1.6, 3.5, 1.5, "7  Random audits", "commit-reveal randomness\nchecks noise + norm bound", TEAL)
box(7.9, 1.6, 3.0, 1.5, "8  Budget check", "contract recomputes ε\nrefuses over-budget", TEAL)
arrow(12.9, 4.1, 3.0, 3.1, RED)
arrow(3.6, 2.35, 4.0, 2.35); arrow(7.5, 2.35, 7.9, 2.35)
box(0.1, 0.1, 13.8, 1.1, "Ledger: hash-chained blocks", "commitments Merkle root · model hash · reputation · per-client ε · audit results"
    "  →  any later edit breaks the chain", NAVY)
arrow(9.4, 1.6, 9.4, 1.2, NAVY)
ax.text(11.4, 2.35, "9  Update global model\nif the round is accepted", fontsize=11.5, fontweight="bold",
        color=NAVY, va="center")
save(fig, "fig0_architecture.png")

# ------------------------------------------------------------------ 7. adaptive audits / ZK norm proofs
def _have(name):
    return os.path.exists(f"{R}/{name}.csv")


if _have("adaptive_audit"):
    ad = pd.read_csv(f"{R}/adaptive_audit.csv")
    scen = ["honest", "persistent sign-flip x10", "sleeper sign-flip (rounds 5-9)"]
    pols = ["no defence (DP+SecAgg)", "audit 25% only", "audit 25% + validation gate", "audit 10% + validation gate",
            "ZK norm proofs (audit 0%)"]
    cols = [RED, ORANGE, TEAL, "#5fbfb3", NAVY]
    fig, ax = plt.subplots(figsize=(13, 5))
    w = 0.16
    for k, (pl, c) in enumerate(zip(pols, cols)):
        mu = [ad[(ad.scenario == sc) & (ad.policy == pl)].acc.mean() for sc in scen]
        sd = [ad[(ad.scenario == sc) & (ad.policy == pl)].acc.std() for sc in scen]
        ax.bar(np.arange(3) + (k - 2) * w, mu, w, yerr=sd, color=c, capsize=3, label=pl)
    ax.set_xticks(range(3))
    ax.set_xticklabels(["honest run", "persistent poisoner\n(sign-flip x10)", "sleeper poisoner\n(turns bad at round 5)"], fontsize=12)
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("final test accuracy")
    ax.set_title("Fixing late detection: validation gate and ZK norm proofs")
    ax.set_title("Fixing late detection: validation gate and ZK norm proofs", pad=46)
    ax.legend(fontsize=9.5, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False)
    save(fig, "fig7_adaptive.png")

# ------------------------------------------------------------------ 8. baselines
if _have("baselines"):
    bl = pd.read_csv(f"{R}/baselines.csv")
    atk = ["honest", "sign-flip x10", "sign-flip x1 (inside the bound)", "label-flip (2 clients)", "sleeper sign-flip x10"]
    systems = ["FedAvg (mean)", "coord. median", "trimmed mean", "Krum", "Multi-Krum", "ours (SecAgg + DP + ledger + gate)"]
    cols = [RED, GREY, "#b8c0cc", "#8d99ae", "#5c677d", TEAL]
    fig, ax = plt.subplots(figsize=(14, 5.2))
    w = 0.13
    for k, (sy, c) in enumerate(zip(systems, cols)):
        mu = [bl[(bl.attack == a) & (bl.system == sy)].acc.mean() for a in atk]
        sd = [bl[(bl.attack == a) & (bl.system == sy)].acc.std() for a in atk]
        lab = sy + ("   [hides updates from the server]" if sy.startswith("ours") else "   [server sees every update]")
        ax.bar(np.arange(len(atk)) + (k - 2.5) * w, mu, w, yerr=sd, color=c, capsize=2.5, label=lab)
    ax.set_xticks(range(len(atk)))
    ax.set_xticklabels(["honest", "sign-flip x10", "sign-flip x1\n(inside the bound)", "label-flip\n(2 clients)", "sleeper\nsign-flip x10"], fontsize=11)
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("final test accuracy")
    ax.set_title("Robust aggregators vs our system: same attacks, very different privacy")
    ax.legend(fontsize=9, loc="lower center", ncol=2, bbox_to_anchor=(0.5, -0.45))
    save(fig, "fig8_baselines.png")

# ------------------------------------------------------------------ 9. second dataset
if _have("covtype"):
    cv = pd.read_csv(f"{R}/covtype.csv")
    order = [("no DP", np.inf), ("distributed DP", 32.0), ("local DP", 32.0), ("distributed DP", 8.0), ("local DP", 8.0)]
    labs, mu, sd = [], [], []
    for st, e in order:
        sub = cv[(cv.setting == st) & ((cv.eps_target == e) | (np.isinf(e) & np.isinf(cv.eps_target)))]
        if len(sub):
            labs.append(st if np.isinf(e) else f"{st}\neps={e:g}")
            mu.append(sub.acc.mean())
            sd.append(sub.acc.std() if len(sub) > 1 else 0)
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(12.5, 4.6))
    a1.bar(labs, mu, yerr=sd, color=[NAVY, TEAL, GREY, TEAL, GREY][:len(labs)], capsize=4)
    a1.set_ylim(0.4, 0.9)
    a1.set_ylabel("test accuracy")
    a1.set_title("Forest Covertype, MLP (1,665 parameters)")
    a1.tick_params(axis="x", labelsize=9.5)
    at = [("sign-flip, no defence", RED), ("sign-flip, audit 25% + gate", TEAL)]
    a2.bar([a[0].replace(", ", ",\n") for a in at], [cv[cv.setting == a[0]].acc.mean() for a in at],
           yerr=[cv[cv.setting == a[0]].acc.std() for a in at], color=[a[1] for a in at], capsize=4)
    a2.set_ylim(0.0, 0.9)
    a2.set_title("Poisoning on the larger dataset")
    save(fig, "fig9_covtype.png")

# ------------------------------------------------------------------ 10. ZK cost
if _have("zk_cost"):
    zc = pd.read_csv(f"{R}/zk_cost.csv")
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11.5, 4.3))
    a1.plot(zc.parameters, zc.prove_s, marker="o", color=TEAL, lw=2.5, label="prove (per hospital)")
    a1.plot(zc.parameters, zc.verify_s, marker="s", color=ORANGE, lw=2.5, label="verify (anyone)")
    a1.set_xlabel("model parameters"); a1.set_ylabel("seconds"); a1.legend(); a1.set_title("ZK norm proof: time")
    a2.plot(zc.parameters, zc.proof_KB, marker="o", color=NAVY, lw=2.5)
    a2.set_xlabel("model parameters"); a2.set_ylabel("KB"); a2.set_title("Proof size")
    save(fig, "fig10_zk_cost.png")

# ------------------------------------------------------------------ 11. real chains
if _have("chain_backends"):
    cb = pd.read_csv(f"{R}/chain_backends.csv")
    fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(14.5, 4.4))
    for bk, c in (("Hardhat (1 node)", TEAL), ("Besu QBFT (4 validators)", NAVY)):
        sub = cb[cb.backend == bk].sort_values("clients")
        a1.plot(sub.clients, sub.seconds_per_round, marker="o", color=c, lw=2.5, label=bk)
        a2.plot(sub.clients, sub.gas_per_round / 1e6, marker="o", color=c, lw=2.5, label=bk)
        a3.plot(sub.clients, sub.verify_gas_per_round / 1e6, marker="o", color=c, lw=2.5, label=bk)
    a1.set_ylabel("seconds per round"); a1.set_title("Latency (QBFT: 1 s block time)"); a1.legend(fontsize=9)
    a2.set_ylabel("million gas per round"); a2.set_title("Total gas, measured")
    a3.set_ylabel("million gas per round"); a3.set_title("On-chain aggregate check")
    for a in (a1, a2, a3):
        a.set_xlabel("hospitals"); a.set_xticks(sorted(cb.clients.unique()))
    save(fig, "fig11_chain_backends.png")

print("done ->", OUT)
