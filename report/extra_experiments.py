"""Extra experiments that produce report-quality data (convergence, MIA ROC, per-hospital accuracy, ablation, epsilon
over rounds, leakage, gas breakdown). Output: report_assets/data/*.csv|json.

    python -m report.extra_experiments            # ~15 min on 8 cores
"""
import itertools, json, os, sys, time, warnings
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
from fedsec.accountant import noise_for_eps
from fedsec.attacks import canary_inference, make_canaries
from fedsec.data import global_test, make_clients
from fedsec.federation import Config, Federation
from fedsec.model import build, evaluate, local_train, predict_logits, per_sample_loss

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report_assets", "data")
os.makedirs(OUT, exist_ok=True)
GRID = np.logspace(-3, 0, 60)


# ------------------------------------------------------------------ one generic job: returns history + extras
def job(args):
    kind, tag, kw, extra = args
    f = Federation(Config(**kw))
    canaries = None
    if extra.get("canaries"):
        ins, outs = make_canaries(f.clients[0].Xtr.shape[1], extra["canaries"], kw.get("seed", 0))
        f.clients[0].Xtr = np.vstack([f.clients[0].Xtr, ins[0]])
        f.clients[0].ytr = np.concatenate([f.clients[0].ytr, ins[1]])
        canaries = (ins, outs)
    res = f.run()
    out = dict(tag)
    out["acc_curve"] = [h["acc"] for h in res["history"]]
    out["auc_curve"] = [h["auc"] for h in res["history"]]
    out["eps_curve"] = [h["eps_max_spent"] for h in res["history"]]
    out["final_acc"], out["final_auc"] = res["final"]["acc"], res["final"]["auc"]
    out["leak_cos"] = res["leak_cos"]
    out["rejected"] = res["rejected_rounds"]
    out["banned"] = list(res["banned"])
    out["events"] = sorted({e["type"] for e in res["events"]})
    out["eps_max"] = max(res["eps"].values())
    out["exposure"] = float(np.mean(list(res["exposure"].values()))) / max(1, kw["rounds"]) if res["exposure"] else 0.0
    if extra.get("per_silo"):
        per = {}
        for c in res["clients"]:
            key = c.name.split("-")[0]
            if key not in per:
                per[key] = evaluate(res["model"], c.Xte, c.yte)["acc"]
        out["per_silo"] = per
    if canaries:
        ins, outs = canaries
        score = -np.concatenate([per_sample_loss(res["model"], *ins), per_sample_loss(res["model"], *outs)])
        lab = np.concatenate([np.ones(len(ins[1])), np.zeros(len(outs[1]))])
        from sklearn.metrics import roc_curve
        fpr, tpr, _ = roc_curve(lab, score)
        out["roc_tpr"] = np.interp(GRID, fpr, tpr).tolist()
        out.update(canary_inference(res["model"], ins, outs))
    return out


def run_all(jobs, workers=None):
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    out = []
    with ProcessPoolExecutor(workers) as ex:
        for i, r in enumerate(ex.map(job, jobs), 1):
            out.append(r)
            print(f"\r  {i}/{len(jobs)}", end="", flush=True)
    print()
    return out


def dump(rows, name):
    json.dump(rows, open(os.path.join(OUT, name + ".json"), "w"))
    print("  ->", name)


def main():
    z10 = noise_for_eps(8, 10)
    z15 = noise_for_eps(8, 15)

    # E1 convergence (accuracy per round), clean and under poisoning --------------------------------
    print("E1 convergence")
    systems = {
        "FedAvg (no privacy)": dict(dp="none", ledger=False, secagg=False),
        "local DP (eps=8)": dict(dp="local", z=z15, ledger=False, secagg=False),
        "ours: SecAgg + distributed DP (eps=8) + ledger": dict(dp="distributed", z=z15, ledger=True, secagg=True),
    }
    jobs = []
    for sd in range(10):
        for sn, sk in systems.items():
            jobs.append(("conv", {"system": sn, "attack": "none", "seed": sd}, dict(rounds=15, n_clients=8, seed=sd, **sk), {}))
        atk = dict(malicious={3: "scale"}, attack_scale=10)
        jobs.append(("conv", {"system": "undefended (DP + SecAgg)", "attack": "sign-flip x10", "seed": sd},
                     dict(rounds=15, n_clients=8, seed=sd, dp="distributed", z=z15, ledger=False, secagg=True, **atk), {}))
        jobs.append(("conv", {"system": "ours: audits 25% + validation gate", "attack": "sign-flip x10", "seed": sd},
                     dict(rounds=15, n_clients=8, seed=sd, dp="distributed", z=z15, ledger=True, secagg=True,
                          audit_rate=0.25, val_gate=True, **atk), {}))
    dump(run_all(jobs), "convergence")

    # E2 membership-inference ROC curves ------------------------------------------------------------
    print("E2 MIA ROC")
    jobs = []
    for sd in range(6):
        for e in (np.inf, 64, 16, 4):
            kw = dict(rounds=20, n_clients=4, hidden=64, local_epochs=30, lr_local=0.1, ledger=False, secagg=False, seed=sd)
            if np.isinf(e):
                kw.update(dp="none", clip=0)
            else:
                kw.update(dp="distributed", clip=1.0, z=noise_for_eps(e, 20))
            jobs.append(("mia", {"eps": "inf" if np.isinf(e) else float(e), "seed": sd}, kw, {"canaries": 50}))
    dump(run_all(jobs), "mia_roc")

    # E3 per-hospital accuracy (the natural non-IID split) ---------------------------------------------
    print("E3 per-hospital accuracy")
    zz = noise_for_eps(8, 8)
    sysk = {"FedAvg (no privacy)": dict(dp="none"), "local DP (eps=8)": dict(dp="local", z=zz),
            "ours: distributed DP (eps=8)": dict(dp="distributed", z=zz)}
    jobs = [("silo", {"system": sn, "seed": sd}, dict(rounds=8, n_clients=4, ledger=False, secagg=False, seed=sd, **sk), {"per_silo": True})
            for sd in range(10) for sn, sk in sysk.items()]
    dump(run_all(jobs), "per_silo")

    # E4 ablation: which layer buys what ----------------------------------------------------------------
    print("E4 ablation")
    layers = {
        "1 FedAvg": dict(dp="none", ledger=False, secagg=False),
        "2 + DP (noise)": dict(dp="distributed", z=z10, ledger=False, secagg=False),
        "3 + SecAgg": dict(dp="distributed", z=z10, ledger=False, secagg=True),
        "4 + ledger (commit, audit, verify)": dict(dp="distributed", z=z10, ledger=True, secagg=True, audit_rate=0.25),
        "5 + validation gate": dict(dp="distributed", z=z10, ledger=True, secagg=True, audit_rate=0.25, val_gate=True),
        "6 + blame phase": dict(dp="distributed", z=z10, ledger=True, secagg=True, audit_rate=0.25, val_gate=True, attribution=True),
    }
    win = (3, 4, 5, 6)
    scen = {
        "honest": {},
        "poisoner (sign-flip x10)": dict(malicious={3: "scale"}, attack_scale=10),
        "stealth forger": dict(malicious={3: "forge"}, attack_scale=10, attack_rounds=win),
        "server reverses aggregate": dict(server_attack="swap_aggregate", attack_rounds=win),
        "client skips DP noise": dict(malicious={3: "noeps"}, audit_rate=0.5),
    }
    jobs = []
    for (ln, lk), (sn, sk), sd in itertools.product(layers.items(), scen.items(), range(8)):
        kw = dict(rounds=10, n_clients=8, seed=sd, **lk)
        kw.update({k: v for k, v in sk.items() if not (k == "audit_rate" and not lk.get("ledger"))})
        jobs.append(("abl", {"layer": ln, "scenario": sn, "seed": sd}, kw, {}))
    dump(run_all(jobs), "ablation")

    # E5 epsilon over rounds, with dropout ---------------------------------------------------------------
    print("E5 epsilon over rounds")
    jobs = [("eps", {"dropout": p, "seed": sd}, dict(rounds=12, n_clients=16, z=noise_for_eps(8, 12), dropout=p, seed=sd, ledger=True), {})
            for p in (0.0, 0.2, 0.4) for sd in range(5)]
    dump(run_all(jobs), "eps_rounds")

    # E6 what the server sees ---------------------------------------------------------------------------------
    print("E6 leakage")
    jobs = [("leak", {"secagg": sa, "clients": n, "seed": sd}, dict(rounds=3, n_clients=n, dp="none", ledger=False, secagg=sa, seed=sd), {})
            for sa in (False, True) for n in (4, 8, 16) for sd in range(8)]
    dump(run_all(jobs), "leakage")

    # E7 gas breakdown on the real chain (sequential) -----------------------------------------------------------
    print("E7 gas breakdown (real chain)")
    f = Federation(Config(rounds=5, n_clients=8, z=noise_for_eps(8, 5), chain="evm", onchain_verify=True, norm_proof="zk",
                          audit_rate=0.25, local_epochs=5, seed=0))
    f.run()
    ct = f.contract
    rows = [{"method": k, "gas": v, "calls": sum(1 for t in ct.tx_log if t["method"] == k)} for k, v in ct.gas_by_method.items()]
    pd.DataFrame(rows).sort_values("gas", ascending=False).to_csv(os.path.join(OUT, "gas_breakdown.csv"), index=False)
    print("  -> gas_breakdown")


if __name__ == "__main__":
    t = time.time()
    main()
    print(f"done in {time.time() - t:.0f}s")
