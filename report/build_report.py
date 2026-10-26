"""Build the report pack:  python -m report.build_report   ->  report_assets/

  figures/   PNG (300 dpi) + PDF (vector) for every figure
  tables/    CSV + Markdown + LaTeX for every table, plus all_tables.xlsx
  data/      raw experiment outputs (CSV / JSON)
  Results_and_Evaluation.docx   a ready-to-edit results chapter with figures, tables and captions
  INDEX.md                      every figure and table with caption, claim and suggested slide
"""
import glob, json, os, re, shutil, subprocess, sys, warnings

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = os.path.join(ROOT, "report_assets")
FIG, TAB, DATA = (os.path.join(A, d) for d in ("figures", "tables", "data"))
R = os.path.join(ROOT, "results")
for d in (FIG, TAB, DATA):
    os.makedirs(d, exist_ok=True)
sys.path.insert(0, ROOT)
from report import diagrams as dg                      # noqa: E402

NAVY, TEAL, ORANGE, RED, GREY, GREEN, GOLD = dg.NAVY, dg.TEAL, dg.ORANGE, dg.RED, dg.GREY, dg.GREEN, dg.GOLD
plt.rcParams.update({"font.size": 12.5, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.alpha": 0.25,
                     "axes.titleweight": "bold", "font.family": "DejaVu Sans"})

FIGS, TABLES = [], []          # registries for the index / docx


def save(fig, name, caption="", slide="", section=""):
    fig.tight_layout()
    fig.savefig(os.path.join(FIG, name + ".png"), dpi=300, bbox_inches="tight", facecolor="white")
    fig.savefig(os.path.join(FIG, name + ".pdf"), bbox_inches="tight", facecolor="white")
    plt.close(fig)
    if caption:
        FIGS.append({"id": name, "caption": caption, "slide": slide, "section": section})
    print("  fig", name)


def table(df, name, caption, section="", index=False, fmt=None):
    df = df.copy()
    df.to_csv(os.path.join(TAB, name + ".csv"), index=index)
    md = df.to_markdown(index=index, floatfmt=fmt or ".3f")
    open(os.path.join(TAB, name + ".md"), "w", encoding="utf-8").write(f"**{caption}**\n\n{md}\n")
    try:
        open(os.path.join(TAB, name + ".tex"), "w", encoding="utf-8").write(
            df.to_latex(index=index, float_format=lambda x: f"{x:.3f}", caption=caption, label="tab:" + name, escape=True))
    except Exception:
        pass
    TABLES.append({"id": name, "caption": caption, "df": df, "section": section, "index": index})
    print("  table", name)


def ms(g, col, nd=3):
    m, s = g[col].mean(), g[col].std()
    return f"{m:.{nd}f} ± {0 if pd.isna(s) else s:.{nd}f}"


def csv(name):
    return pd.read_csv(os.path.join(R, name + ".csv"))


def js(name):
    p = os.path.join(DATA, name + ".json")
    return json.load(open(p)) if os.path.exists(p) else []


# =====================================================================================================
# 0. raw data copy + existing figures regenerated at print quality
# =====================================================================================================
def copy_data():
    for f in glob.glob(os.path.join(R, "*.csv")) + glob.glob(os.path.join(R, "*.md")):
        shutil.copy(f, DATA)


RENAME = {
    "fig1_privacy_utility": ("F02_privacy_vs_accuracy", "Privacy-utility trade-off. Left: test accuracy against the privacy budget epsilon for local DP (every hospital adds full noise) and our distributed DP under secure aggregation (noise split across hospitals); dashed line is FedAvg without privacy. Right: with epsilon fixed at 8, fewer communication rounds are better under DP. Mean +/- 1 s.d. over 8 seeds; four real hospital silos.", "slide 17", "RQ1"),
    "fig2_membership": ("F03_membership_inference", "Membership inference on 50 planted canary records against an over-fitted model. Attacker AUC falls from 0.66 without DP to chance (0.5) for epsilon <= 16; bars annotate the accuracy cost. Mean +/- s.d. over 5 seeds.", "slide 18", "RQ2"),
    "fig3_attacks": ("F06_attacks_undefended_vs_defended", "Seven attacks against the undefended system (DP + secure aggregation) and the full system. Labels show whether the full system detected the attack; label-flipping inside the norm bound is the stated limit. 20 seeds.", "slides 20-21", "RQ2"),
    "fig4_audit_tradeoff": ("F13_audit_rate_tradeoff", "Audit-rate trade-off. Left: the seeded-noise audit catches a hospital that skips its DP noise (statistical audit never does at 14 parameters). Middle: accuracy with a poisoner present against audit rate. Right: the price, the share of rounds in which an honest hospital is opened.", "slide 22", "RQ2"),
    "fig5_overhead": ("F16_overhead_vs_clients", "Overhead of each layer against the number of hospitals: communication per hospital per round, compute per round, and measured gas on the real chain.", "slide 23", "RQ3"),
    "fig6_dropout": ("F15_dropout_tolerance", "Dropout tolerance. Left: rounds completed against the share of hospitals that disconnect. Right: epsilon actually spent; the contract charges the real cost, which rises with dropout because dropped hospitals take their noise share with them.", "slide 24", "RQ3"),
    "fig7_adaptive": ("F07_fixing_late_detection", "Fixing late detection. Random audits alone leave large variance (a late catch leaves a damaged model); the validation gate and the zero-knowledge norm proofs restore accuracy for persistent and sleeper poisoners. 16 seeds (ZK: 8).", "slide 22 (new)", "RQ2"),
    "fig8_baselines": ("F09_vs_robust_aggregation", "Comparison with robust aggregation. Krum, median and trimmed mean resist the same attacks but require the server to see every individual update; ours hides all updates from the server at a small accuracy cost. 16 seeds.", "new slide", "RQ2"),
    "fig9_covtype": ("F20_second_dataset_covertype", "Second dataset (Forest Covertype, 4 wilderness-area silos, MLP with 1,665 parameters). Client-level DP is expensive at this size and distributed DP shows no advantage over local DP with only 4 clients (a negative result); poisoning is only partly recovered.", "backup slide", "RQ5"),
    "fig10_zk_cost": ("F17_zk_proof_cost", "Cost of the zero-knowledge norm proof against model size: linear in the number of parameters (0.3 s at 14 parameters, 2.9 s at 256), so practical only for small models.", "new slide", "RQ3"),
    "fig11_chain_backends": ("F18_chain_backends", "The same federation on one Hardhat node and on a real 4-validator QBFT network, with the contract verifying the aggregate. Gas differs because newer EVM hard forks reprice modexp.", "slide 23", "RQ3"),
}


def regenerate_existing():
    raw = os.path.join(FIG, "_raw")
    os.makedirs(raw, exist_ok=True)
    env = dict(os.environ, FEDSEC_FIG_DIR=raw, FEDSEC_FIG_DPI="300", FEDSEC_FIG_PDF="1", PYTHONPATH=ROOT)
    subprocess.run([sys.executable, "make_figures.py"], cwd=ROOT, env=env, check=True, capture_output=True)
    for old, (new, cap, slide, sec) in RENAME.items():
        for ext in ("png", "pdf"):
            src = os.path.join(raw, f"{old}.{ext}")
            if os.path.exists(src):
                shutil.copy(src, os.path.join(FIG, f"{new}.{ext}"))
        FIGS.append({"id": new, "caption": cap, "slide": slide, "section": sec})
        print("  fig", new)
    shutil.rmtree(raw)


# =====================================================================================================
# 1. new data figures
# =====================================================================================================
def fig_roc():
    rows = js("mia_roc")
    if not rows:
        return
    G = np.logspace(-3, 0, 60)
    fig, ax = plt.subplots(figsize=(7.2, 6))
    cols = {"inf": RED, "64.0": ORANGE, "16.0": TEAL, "4.0": NAVY}
    for e, c in cols.items():
        sub = [r for r in rows if str(r["eps"]) == e]
        if not sub:
            continue
        tpr = np.mean([r["roc_tpr"] for r in sub], axis=0)
        auc = np.mean([r["canary_auc"] for r in sub])
        ax.plot(G, tpr, color=c, lw=2.5, label=("no DP" if e == "inf" else f"epsilon = {float(e):g}") + f"   (AUC {auc:.2f})")
    ax.plot([1e-3, 1], [1e-3, 1], "--", color=GREY, label="random guessing")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("false positive rate"); ax.set_ylabel("true positive rate")
    ax.set_title("Membership-inference ROC (log-log)")
    ax.legend(fontsize=10, loc="lower right")
    save(fig, "F04_mia_roc_curves", "ROC curves of the loss-threshold membership-inference attack on planted canary records (log-log, the low-false-positive regime that matters for privacy). Without DP the curve lies above the diagonal; at epsilon <= 16 it collapses onto it. Mean over 6 seeds.", "slide 18 (alt.)", "RQ2")


def fig_leakage():
    rows = js("leakage")
    if not rows:
        return
    df = pd.DataFrame(rows)
    fig, ax = plt.subplots(figsize=(8.5, 5))
    w = 0.34
    ns = sorted(df.clients.unique())
    for k, (sa, c, lab) in enumerate(((False, RED, "no secure aggregation"), (True, TEAL, "secure aggregation"))):
        m = [df[(df.secagg == sa) & (df.clients == n)].leak_cos.mean() for n in ns]
        s = [df[(df.secagg == sa) & (df.clients == n)].leak_cos.std() for n in ns]
        ax.bar(np.arange(len(ns)) + (k - 0.5) * w, m, w, yerr=s, color=c, capsize=4, label=lab)
    ax.set_xticks(range(len(ns))); ax.set_xticklabels([f"{n} hospitals" for n in ns])
    ax.axhline(0, color=NAVY, lw=1)
    ax.set_ylim(-0.15, 1.15); ax.set_ylabel("similarity of the server's copy to the true update")
    ax.set_title("What the server sees"); ax.legend(loc="center right")
    save(fig, "F05_server_view_leakage", "Cosine similarity between what the server receives from a hospital and that hospital's true update. Without secure aggregation the server reads every update (1.0); with it the similarity is zero for 4, 8 and 16 hospitals. 8 seeds.", "slide 19", "RQ2")


def fig_pareto():
    ad = csv("adaptive_audit")
    ad["caught"] = (ad.banned.fillna("") != "").astype(int)
    fig, axs = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
    cols = {"no defence (DP+SecAgg)": RED, "audit 25% only": ORANGE, "audit 25% + validation gate": TEAL,
            "audit 10% + validation gate": "#5fbfb3", "ZK norm proofs (audit 0%)": NAVY}
    for ax, sc in zip(axs, ("persistent sign-flip x10", "sleeper sign-flip (rounds 5-9)")):
        for pol, c in cols.items():
            g = ad[(ad.scenario == sc) & (ad.policy == pol)]
            ax.errorbar(g.honest_exposure.mean(), g.acc.mean(), yerr=g.acc.std(), fmt="o", ms=11, color=c, capsize=4, label=pol)
        ax.set_xlabel("share of rounds an honest hospital is opened (privacy cost)")
        ax.set_title(sc.replace(" (rounds 5-9)", ""))
        ax.set_xlim(-0.03, 0.62)
    axs[0].set_ylabel("final accuracy (security benefit)")
    axs[0].legend(fontsize=9, loc="lower right")
    save(fig, "F08_accuracy_vs_exposure", "Security against privacy exposure for each defence policy. ZK norm proofs reach the best accuracy with zero exposure of any hospital's data; the validation gate buys accuracy by opening honest hospitals in a third to a half of the rounds. Up and to the left is better.", "new slide", "RQ2")


def fig_convergence():
    rows = js("convergence")
    if not rows:
        return
    df = pd.DataFrame(rows)
    fig, axs = plt.subplots(1, 2, figsize=(14, 5), sharey=True)
    for ax, atk, ttl in ((axs[0], "none", "Honest hospitals"), (axs[1], "sign-flip x10", "One poisoner (sign-flip x10)")):
        sub = df[df.attack == atk]
        for (sn, c) in (("FedAvg (no privacy)", NAVY), ("local DP (eps=8)", GREY), ("ours: SecAgg + distributed DP (eps=8) + ledger", TEAL),
                        ("undefended (DP + SecAgg)", RED), ("ours: audits 25% + validation gate", TEAL)):
            g = sub[sub.system == sn]
            if g.empty:
                continue
            A_ = np.array(list(g.acc_curve))
            m, s = A_.mean(0), A_.std(0)
            x = np.arange(1, len(m) + 1)
            ax.plot(x, m, color=c, lw=2.5, label=sn)
            ax.fill_between(x, m - s, m + s, color=c, alpha=0.15)
        ax.set_xlabel("communication round"); ax.set_title(ttl); ax.legend(fontsize=9, loc="lower right")
    axs[0].set_ylabel("test accuracy")
    save(fig, "F11_convergence_curves", "Test accuracy per round (mean +/- s.d., 10 seeds, 8 hospitals, epsilon = 8 over 15 rounds). Our system tracks FedAvg closely and clearly beats local DP; under a sign-flip poisoner the undefended model is destroyed while the defended one recovers after the attacker is banned.", "slide 17/21 (alt.)", "RQ1")


def fig_silo():
    rows = js("per_silo")
    if not rows:
        return
    df = pd.DataFrame(rows)
    silos = ["cleveland", "hungarian", "switzerland", "va"]
    fig, ax = plt.subplots(figsize=(10, 5))
    w = 0.26
    for k, (sn, c) in enumerate((("FedAvg (no privacy)", NAVY), ("local DP (eps=8)", GREY), ("ours: distributed DP (eps=8)", TEAL))):
        g = df[df.system == sn]
        m = [np.mean([d[s] for d in g.per_silo]) for s in silos]
        sd = [np.std([d[s] for d in g.per_silo]) for s in silos]
        ax.bar(np.arange(4) + (k - 1) * w, m, w, yerr=sd, color=c, capsize=3, label=sn)
    ax.set_xticks(range(4)); ax.set_xticklabels(["Cleveland", "Hungarian", "Switzerland", "VA"])
    ax.set_ylim(0.3, 1.0); ax.set_ylabel("accuracy on that hospital's own test set")
    ax.set_title("Who benefits? Accuracy per hospital (non-IID silos)"); ax.legend(fontsize=9.5, loc="lower right")
    save(fig, "F12_per_hospital_accuracy", "Accuracy on each hospital's own held-out patients. The four real silos differ in size and case mix, so DP noise does not cost every hospital equally; 10 seeds, 4 hospitals, epsilon = 8.", "backup slide", "RQ5")


def fig_ablation():
    rows = js("ablation")
    if not rows:
        return
    df = pd.DataFrame(rows)
    layers = sorted(df.layer.unique())
    scen = ["honest", "poisoner (sign-flip x10)", "stealth forger", "server reverses aggregate", "client skips DP noise"]
    det = lambda r: 1 if (r["banned"] or [e for e in r["events"] if e in ("audit_fail", "aggregate_verification_failed", "survivor_mismatch", "gate_rejected", "forger_identified", "server_blamed")]) else 0
    df["detected"] = df.apply(det, axis=1)
    acc = np.array([[df[(df.layer == l) & (df.scenario == s)].final_acc.mean() for s in scen] for l in layers])
    dt = np.array([[df[(df.layer == l) & (df.scenario == s)].detected.mean() for s in scen] for l in layers])
    fig, axs = plt.subplots(1, 2, figsize=(15, 5.6), sharey=True)
    for ax, M, ttl, cm, fmtf in ((axs[0], acc, "Final accuracy", "RdYlGn", "{:.2f}"), (axs[1], dt, "Attack detected (share of runs)", "Blues", "{:.0%}")):
        im = ax.imshow(M, cmap=cm, vmin=0 if cm == "Blues" else 0.2, vmax=1, aspect="auto")
        ax.set_xticks(range(len(scen))); ax.set_xticklabels([s.replace(" (", "\n(") for s in scen], fontsize=9.5)
        ax.set_yticks(range(len(layers))); ax.set_yticklabels(layers, fontsize=10.5)
        for i in range(M.shape[0]):
            for j in range(M.shape[1]):
                ax.text(j, i, fmtf.format(M[i, j]), ha="center", va="center", fontsize=10.5, color="black")
        ax.set_title(ttl); ax.grid(False)
        ax.xaxis.tick_top()
    save(fig, "F10_ablation_layers", "Ablation: what each layer buys. Rows add one component at a time (FedAvg -> + DP -> + secure aggregation -> + ledger (commit, audit, verify) -> + validation gate -> + blame phase); columns are scenarios. Left: final accuracy. Right: whether the attack was detected. The gate rows train on 8% less data (held out as the public validation set), which costs about 0.02 on the honest run. 8 seeds, 8 hospitals.", "new slide", "RQ2")


def fig_eps_rounds():
    rows = js("eps_rounds")
    if not rows:
        return
    df = pd.DataFrame(rows)
    fig, ax = plt.subplots(figsize=(8.5, 5))
    for p, c in ((0.0, TEAL), (0.2, ORANGE), (0.4, RED)):
        g = df[df.dropout == p]
        A_ = np.array(list(g.eps_curve))
        m, s = A_.mean(0), A_.std(0)
        x = np.arange(1, len(m) + 1)
        ax.plot(x, m, color=c, lw=2.5, label=f"{int(p * 100)}% of hospitals drop out")
        ax.fill_between(x, m - s, m + s, color=c, alpha=0.15)
    ax.axhline(8, color=NAVY, ls="--"); ax.text(1, 8.15, "planned epsilon = 8", color=NAVY, fontsize=10)
    ax.set_xlabel("round"); ax.set_ylabel("epsilon spent (largest across hospitals, on-chain)")
    ax.set_title("The contract charges the real privacy cost"); ax.legend(loc="upper left", fontsize=10)
    save(fig, "F14_epsilon_over_rounds", "Privacy budget consumed per round as recorded by the contract, with 16 hospitals and 0/20/40% dropout (5 seeds). Dropped hospitals take their noise share with them, so the effective noise falls and epsilon grows faster than planned.", "slide 24 (alt.)", "RQ3")


def fig_gas():
    p = os.path.join(DATA, "gas_breakdown.csv")
    if not os.path.exists(p):
        return
    g = pd.read_csv(p).sort_values("gas")
    fig, ax = plt.subplots(figsize=(9, 5.6))
    ax.barh(g.method, g.gas / 1e6, color=TEAL)
    for i, (v, c) in enumerate(zip(g.gas / 1e6, g.calls)):
        ax.text(v + 0.02, i, f"{v:.2f}M  ({c} calls)", va="center", fontsize=9)
    ax.set_xlabel("gas for the whole run, millions (measured)"); ax.set_xlim(0, g.gas.max() / 1e6 * 1.25)
    ax.set_title("Where the gas goes (8 hospitals, 5 rounds, on-chain verification)"); ax.grid(axis="y", visible=False)
    save(fig, "F19_gas_breakdown", "Measured gas by contract method for 5 rounds with 8 hospitals, on-chain verification of the aggregate and ZK proof hashes. Round opening and the on-chain homomorphic check dominate.", "slide 23 (alt.)", "RQ3")


def fig_pareto_privacy_cost():
    pass


# =====================================================================================================
# 2. tables
# =====================================================================================================
def make_tables():
    pu = csv("privacy_utility")
    t = pu[pu.rounds.isin([0, 5])].groupby(["setting", "eps_target"]).apply(
        lambda g: pd.Series({"accuracy": ms(g, "acc"), "AUC": ms(g, "auc"), "runs": len(g)})).reset_index()
    t["eps_target"] = t.eps_target.replace(np.inf, "none")
    table(t, "T01_privacy_utility", "Privacy-utility trade-off (5 rounds, 8 seeds, mean ± s.d.).", "RQ1")
    t = pu[pu.eps_target == 8].groupby(["setting", "rounds"]).apply(lambda g: pd.Series({"accuracy": ms(g, "acc"), "AUC": ms(g, "auc")})).reset_index()
    table(t, "T02_rounds_ablation", "Effect of the number of communication rounds at epsilon = 8.", "RQ1")

    m = csv("membership")
    t = m.groupby("eps_target").apply(lambda g: pd.Series({"model accuracy": ms(g, "acc"), "canary AUC": ms(g, "canary_auc"),
                                                          "TPR @ 10% FPR": ms(g, "canary_tpr@10%fpr")})).reset_index()
    t["eps_target"] = t.eps_target.replace(np.inf, "no DP")
    table(t, "T03_membership_inference", "Membership inference on planted canary records (5 seeds).", "RQ2")

    a = csv("attacks")
    a["detected"] = a.detected.astype(float)
    t = a.groupby(["attack", "defence"]).apply(lambda g: pd.Series({"accuracy": ms(g, "acc", 2), "detected": f"{g.detected.mean():.0%}",
                                                                    "rejected rounds": f"{g.rejected_rounds.mean():.1f}", "seeds": len(g)})).reset_index()
    table(t, "T04_attack_matrix", "Attack matrix: undefended vs defended (20 seeds).", "RQ2")

    ad = csv("adaptive_audit")
    ad["caught"] = (ad.banned.fillna("") != "").astype(int)
    t = ad.groupby(["scenario", "policy"]).apply(lambda g: pd.Series({"accuracy": ms(g, "acc"), "attacker banned": f"{g.caught.mean():.0%}",
                                                                      "emergency audits / run": f"{g.emergency_rounds.mean():.2f}",
                                                                      "honest exposure": f"{g.honest_exposure.mean():.2f}", "seeds": len(g)})).reset_index()
    table(t, "T05_adaptive_defences", "Audit policies against persistent and sleeper poisoners.", "RQ2")

    b = csv("baselines")
    t = b.groupby(["system", "attack"]).apply(lambda g: ms(g, "acc", 3)).unstack()
    t = t.reset_index()
    t.insert(1, "server sees updates", ["no" if s.startswith("ours") else "yes" for s in t.system])
    table(t, "T06_vs_robust_aggregation", "Accuracy under attack: robust aggregation baselines vs our system (16 seeds).", "RQ2")

    ab = js("ablation")
    if ab:
        df = pd.DataFrame(ab)
        t = df.groupby(["layer", "scenario"]).apply(lambda g: f"{g.final_acc.mean():.2f}").unstack().reset_index()
        table(t, "T13_ablation_accuracy", "Ablation: final accuracy as layers are added (8 seeds).", "RQ2")
    ps = js("per_silo")
    if ps:
        df = pd.DataFrame(ps)
        rows = []
        for sn, g in df.groupby("system"):
            rows.append({"system": sn, **{s: f"{np.mean([d[s] for d in g.per_silo]):.3f} ± {np.std([d[s] for d in g.per_silo]):.3f}" for s in ("cleveland", "hungarian", "switzerland", "va")}})
        table(pd.DataFrame(rows), "T14_per_hospital_accuracy", "Accuracy on each hospital's own test set (10 seeds, epsilon = 8).", "RQ5")

    cv = csv("covtype")
    t = cv.groupby(["setting", "eps_target"]).apply(lambda g: pd.Series({"accuracy": ms(g, "acc"), "AUC": ms(g, "auc"), "seeds": len(g)})).reset_index()
    t["eps_target"] = t.eps_target.replace(np.inf, "none")
    table(t, "T07_second_dataset", "Forest Covertype, MLP with 1,665 parameters (4 seeds).", "RQ5")

    zk = csv("zk_cost")
    table(zk, "T08_zk_cost", "Zero-knowledge norm proof: cost against model size.", "RQ3")
    cb = csv("chain_backends")
    table(cb, "T09_chain_backends", "Real chains with on-chain verification: Hardhat (1 node) vs Besu QBFT (4 validators).", "RQ3")
    co = csv("chain_overhead")
    table(co, "T10_chain_overhead", "Measured gas and latency on the real chain vs number of hospitals (5 rounds).", "RQ3")
    di = csv("distributed")
    table(di, "T11_distributed_run", "Distributed run: server and hospitals as separate OS processes (one with a real crash).", "RQ3")
    dr = csv("dropout")
    t = dr.groupby("dropout").apply(lambda g: pd.Series({"accuracy": ms(g, "acc"), "rounds completed": f"{g.accepted_rounds.mean():.1f}",
                                                         "epsilon spent": f"{g.eps_max.mean():.2f}"})).reset_index()
    table(t, "T12_dropout", "Dropout tolerance with 16 hospitals (3 seeds).", "RQ3")
    at = csv("audit_tradeoff")
    at["caught"] = (at.banned.fillna("") != "").astype(int)
    t = at.groupby(["attacker", "audit_mode", "audit_rate"]).apply(lambda g: pd.Series({
        "accuracy": ms(g, "acc"), "caught": f"{g.caught.mean():.0%}", "first detection round": f"{g.first_event_round[g.first_event_round >= 0].mean():.1f}" if (g.first_event_round >= 0).any() else "-",
        "honest exposure": f"{g.honest_exposure.mean():.2f}"})).reset_index()
    table(t, "T15_audit_tradeoff", "Audit rate, audit mode and detection (20 seeds).", "RQ2")
    ov = csv("overhead")
    t = ov[["clients", "variant", "time_per_round_s", "bytes_per_client_round", "gas_per_round"]].round(2)
    table(t, "T16_overhead_simulated", "Per-layer overhead against number of hospitals (simulated ledger: gas is an estimate).", "RQ3")
    g = os.path.join(DATA, "gas_breakdown.csv")
    if os.path.exists(g):
        table(pd.read_csv(g), "T17_gas_breakdown", "Measured gas by contract method (8 hospitals, 5 rounds).", "RQ3")

    # experimental setup
    sys.path.insert(0, ROOT)
    from fedsec.data import SILOS, _load_silo
    rows = []
    for s in SILOS:
        X, y = _load_silo(s)
        rows.append({"hospital (silo)": s.title() if s != "va" else "VA", "patients": len(y), "positive (heart disease)": int(y.sum()),
                     "prevalence": f"{y.mean():.2f}", "features": X.shape[1]})
    rows.append({"hospital (silo)": "total", "patients": sum(r["patients"] for r in rows), "positive (heart disease)": sum(r["positive (heart disease)"] for r in rows),
                 "prevalence": "", "features": 13})
    table(pd.DataFrame(rows), "T18_dataset", "UCI Heart Disease: the four real hospital silos (75% train / 25% test per silo).", "setup")
    from fedsec.federation import Config
    c = Config()
    setup = [("model", "logistic regression (13+1 parameters); MLP (1,665) on Covertype"), ("local training", f"{c.local_epochs} epochs SGD, lr {c.lr_local}, batch 32"),
             ("update clipping", f"L2 norm C = {c.clip}"), ("differential privacy", "client-level Gaussian mechanism, RDP accountant, delta = 1e-5"),
             ("noise split", "distributed: sigma = zC/sqrt(h); local: sigma = zC"), ("secure aggregation", "X25519 pairwise masks + self mask, Shamir threshold floor(n/2)+1"),
             ("commitments", "Pedersen vector commitments, 1024-bit Schnorr group, 256-bit order"), ("ZK norm proof", "Sigma protocols + bit-decomposition range proof (Fiat-Shamir)"),
             ("fixed point", "2^20"), ("audit rate", f"{c.audit_rate} (default)"), ("ledger", "Solidity 0.8.24 contract; Hardhat chain or Besu QBFT (4 validators)"),
             ("seeds", "5-20 per experiment, reported as mean ± s.d.")]
    table(pd.DataFrame(setup, columns=["parameter", "value"]), "T19_experimental_setup", "Experimental setup.", "setup")

    cov = pd.DataFrame(dg.COVER, index=dg.ATTACKS, columns=[m.replace("\n", " ") for m in dg.MECH]).replace({2: "primary", 1: "partial", 0: ""})
    table(cov.reset_index().rename(columns={"index": "attack"}), "T20_defence_coverage", "Which defence stops which attack.", "design")
    tests = []
    for f in sorted(glob.glob(os.path.join(ROOT, "tests", "test_*.py"))):
        tests.append({"test file": os.path.basename(f), "tests": len(re.findall(r"^def test_", open(f, encoding="utf-8").read(), flags=re.M))})
    tests.append({"test file": "total", "tests": sum(t["tests"] for t in tests)})
    table(pd.DataFrame(tests), "T21_test_inventory", "Automated tests (parametrised cases not expanded).", "reproducibility")
    lim = [("TEE-based audit", "not implemented: needs secure-enclave hardware"), ("Shapley rewards", "not implemented: need individual updates, hidden by secure aggregation; stake/slash/reward used instead"),
           ("Noise correctness", "audited (seeded audit), not proven in zero knowledge"), ("Label-flip inside the norm bound", "bounded, not detected"),
           ("Robust aggregation baselines", "match or beat our accuracy under attack but see every individual update"),
           ("Covertype (MLP, 4 clients)", "client-level DP is expensive; no advantage of distributed DP"), ("ZK proof cost", "linear in parameters; impractical beyond a few hundred"),
           ("Secure aggregation", "passive-secure against the server (no consistency round)"), ("Chain", "one Hardhat node = no consensus; Besu QBFT = 4 validators on one machine"),
           ("Cryptographic parameters", "demo-sized (1024-bit group)")]
    table(pd.DataFrame(lim, columns=["limitation", "status"]), "T22_limitations", "Known limitations and what is not claimed.", "limits")


def write_xlsx():
    from openpyxl.utils import get_column_letter
    with pd.ExcelWriter(os.path.join(TAB, "all_tables.xlsx"), engine="openpyxl") as xw:
        for t in TABLES:
            df = t["df"]
            sheet = t["id"][:31]
            df.to_excel(xw, sheet_name=sheet, index=t["index"])
            ws = xw.sheets[sheet]
            for i, col in enumerate(df.reset_index().columns if t["index"] else df.columns, 1):
                width = max(len(str(col)), *(len(str(v)) for v in (df.reset_index()[col] if t["index"] else df[col]))) + 2
                ws.column_dimensions[get_column_letter(i)].width = min(width, 60)
            ws.freeze_panes = "A2"


# =====================================================================================================
# 3. Word chapter + index
# =====================================================================================================
SECTIONS = [
    ("1  Experimental setup", "setup", "All experiments use four real hospital silos (UCI Heart Disease). Results are means ± standard deviations over several random seeds; each table states its seed count."),
    ("2  Privacy and utility", "RQ1", "How much accuracy does privacy cost, and does splitting the noise across hospitals under secure aggregation help?"),
    ("3  What the system protects against", "RQ2", "Membership inference, a curious server, malicious hospitals and a malicious server, and the defences that stop them."),
    ("4  Cost and robustness of the system", "RQ3", "Overhead of each layer, the real blockchain, the ZK proof, dropout, and a genuinely distributed run."),
    ("5  Generality and fairness", "RQ5", "A second dataset, and accuracy for each hospital."),
    ("6  Design and threat model", "design", "Architecture and defence coverage."),
    ("7  Limitations", "limits", "What is not claimed."),
]


def build_docx():
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Inches, Pt
    doc = Document()
    st = doc.styles["Normal"]
    st.font.name, st.font.size = "Calibri", Pt(11)
    doc.add_heading("Results and Evaluation", 0)
    doc.add_paragraph("Secure Federated Intelligence Platform: federated learning across hospitals with secure aggregation, "
                      "distributed differential privacy and a verifiable blockchain ledger. All numbers are produced by the code in this "
                      "repository (`python -m experiments.run_experiments all`, `python -m report.build_report`).")
    fig_by_sec = {}
    for f in FIGS:
        fig_by_sec.setdefault(f["section"] or "design", []).append(f)
    tab_by_sec = {}
    for t in TABLES:
        tab_by_sec.setdefault(t["section"] or "design", []).append(t)
    fig_no, tab_no = 0, 0
    for title, key, intro in SECTIONS:
        doc.add_heading(title, 1)
        doc.add_paragraph(intro)
        for t in tab_by_sec.get(key, []):
            tab_no += 1
            doc.add_paragraph().add_run(f"Table {tab_no}. {t['caption']}").bold = True
            df = t["df"].reset_index() if t["index"] else t["df"]
            if len(df) > 40:
                df = df.head(40)
            tb = doc.add_table(rows=1, cols=len(df.columns))
            tb.style = "Light Grid Accent 1"
            for i, c in enumerate(df.columns):
                tb.rows[0].cells[i].text = str(c)
            for _, row in df.iterrows():
                cells = tb.add_row().cells
                for i, v in enumerate(row):
                    cells[i].text = f"{v:.3f}" if isinstance(v, float) else str(v)
            for r in tb.rows:
                for c in r.cells:
                    for p in c.paragraphs:
                        for run in p.runs:
                            run.font.size = Pt(8.5)
            doc.add_paragraph()
        for f in fig_by_sec.get(key, []):
            png = os.path.join(FIG, f["id"] + ".png")
            if os.path.exists(png):
                fig_no += 1
                doc.add_picture(png, width=Inches(6.4))
                doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
                p = doc.add_paragraph()
                p.add_run(f"Figure {fig_no}. ").bold = True
                p.add_run(f["caption"])
    doc.save(os.path.join(A, "Results_and_Evaluation.docx"))
    print("  docx saved")


def write_index():
    lines = ["# Report pack index", "",
             "Everything here is generated by `python -m report.build_report` from the experiment outputs in `data/`.", "",
             "## Figures (`figures/`, each as .png 300 dpi and .pdf vector)", "", "| id | what it shows | suggested slide |", "|---|---|---|"]
    for f in sorted(FIGS, key=lambda x: x["id"]):
        cap = f["caption"].replace("|", "/")
        lines.append(f"| `{f['id']}` | {cap} | {f['slide']} |")
    lines += ["", "## Tables (`tables/`: .csv, .md, .tex, and all_tables.xlsx with one sheet each)", "", "| id | caption |", "|---|---|"]
    for t in TABLES:
        lines.append(f"| `{t['id']}` | {t['caption']} |")
    lines += ["", "## Other files", "", "* `Results_and_Evaluation.docx` - a results chapter with all figures, tables and captions, ready to edit",
              "* `data/` - raw experiment outputs (CSV / JSON) and `demo_attacks*.md`", "* `HEADLINES.md` - the numbers to quote and the honest caveats"]
    open(os.path.join(A, "INDEX.md"), "w", encoding="utf-8").write("\n".join(lines) + "\n")


def main():
    print("data"); copy_data()
    print("existing figures at print quality"); regenerate_existing()
    print("diagrams")
    dg_save = lambda fig, name: save(fig, name)
    for fn, cap, slide, sec in ((dg.architecture, "System architecture: hospitals, an untrusted server and the contract on a BFT chain; green marks zero-knowledge and on-chain verification.", "architecture slide", "design"),
                                (dg.zk_protocol, "The zero-knowledge proof that a committed update has bounded L2 norm: per-coordinate commitments and a Sigma proof of squares, a slack commitment, and a bit-decomposition range proof.", "new slide", "design"),
                                (dg.coverage, "Defence coverage: which mechanism is the primary defence (filled) or a contributing one (open) for each attack. Each row is backed by a test and an experiment.", "slide 20 (alt.)", "design"),
                                (dg.qbft, "Real multi-node blockchain: 4 Besu validators on QBFT consensus tolerate 1 fault and halt safely with 2 down.", "new slide", "design"),
                                (dg.swimlane, "One federated round as messages between separate OS processes: hospitals, the untrusted server and the contract.", "new slide", "design")):
        fn(lambda fig, name, _c=cap, _s=slide, _sec=sec: save(fig, name, _c, _s, _sec))
    print("data figures")
    for f in (fig_roc, fig_leakage, fig_pareto, fig_convergence, fig_silo, fig_ablation, fig_eps_rounds, fig_gas):
        f()
    print("tables"); make_tables(); write_xlsx()
    print("docx + index"); build_docx(); write_index()
    json.dump({"figures": FIGS, "tables": [{k: v for k, v in t.items() if k != "df"} for t in TABLES]}, open(os.path.join(A, "manifest.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
