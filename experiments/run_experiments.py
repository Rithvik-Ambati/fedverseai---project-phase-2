"""Research experiments. Usage:

    python -m experiments.run_experiments privacy_utility
    python -m experiments.run_experiments attacks
    python -m experiments.run_experiments overhead
    python -m experiments.run_experiments audit_tradeoff
    python -m experiments.run_experiments dropout
    python -m experiments.run_experiments all          (add --quick for a fast smoke run)

Every experiment writes results/<name>.csv (one row per run) and prints a summary table.
Runs are independent and executed in a process pool.
"""
import argparse, itertools, os, sys, time
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd

from fedsec.accountant import eps_for, noise_for_eps
from fedsec.attacks import canary_inference, make_canaries, membership_inference
from fedsec.data import global_test, make_clients
from fedsec.federation import Config, Federation
from fedsec.model import build, evaluate, local_train

RESULTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
EVENT_KINDS = {"audit_fail", "aggregate_verification_failed", "survivor_mismatch"}


# ------------------------------------------------------------------ one run
def one_run(job):
    tag, cfg_kwargs, extra = job
    cfg = Config(**cfg_kwargs)
    canaries = None
    if extra.get("warmup"):                       # keep one-off import / JIT costs out of the timings
        Federation(Config(**{**cfg_kwargs, "rounds": 1})).run()
    t0 = time.time()
    f = Federation(cfg)
    if extra.get("canaries"):                     # plant canary records in client 0's training set
        ins, outs = make_canaries(f.clients[0].Xtr.shape[1], extra["canaries"], cfg.seed)
        f.clients[0].Xtr = np.vstack([f.clients[0].Xtr, ins[0]])
        f.clients[0].ytr = np.concatenate([f.clients[0].ytr, ins[1]])
        canaries = (ins, outs)
    res = f.run()
    row = dict(tag)
    row.update({k: res["final"].get(k) for k in ("acc", "auc", "loss")})
    row["eps_max"] = max(res["eps"].values())
    row["rejected_rounds"] = res["rejected_rounds"]
    row["banned"] = ",".join(map(str, res["banned"]))
    row["leak_cos"] = res["leak_cos"]
    row["emergency_rounds"] = sum(h["emergency"] for h in res["history"])
    ev = res["events"]
    row["n_events"] = len([e for e in ev if e["type"] in EVENT_KINDS])
    row["first_event_round"] = min([e["round"] for e in ev if e["type"] in EVENT_KINDS], default=-1)
    row["refused_events"] = len([e for e in ev if e["type"] == "refused"])
    mal = set(cfg.malicious)
    honest = [c.cid for c in res["clients"] if c.cid not in mal]
    row["honest_exposure"] = float(np.mean([res["exposure"].get(c, 0) for c in honest])) / max(1, cfg.rounds)
    row["accepted_rounds"] = cfg.rounds - res["rejected_rounds"]
    for k, v in res["timers"].items():
        row[f"t_{k}"] = v / cfg.rounds
    for k, v in res["bytes"].items():
        row[f"bytes_{k}"] = v / cfg.rounds
    row["gas_per_round"] = res.get("gas", 0) / cfg.rounds
    row["wall_s"] = time.time() - t0
    if extra.get("mia"):
        row.update(membership_inference(res["model"], res["clients"], seed=cfg.seed))
    if canaries:
        row.update(canary_inference(res["model"], *canaries))
    return row


def pmap(jobs, workers=None):
    workers = workers or max(1, (os.cpu_count() or 2) - 1)
    out = []
    with ProcessPoolExecutor(workers) as ex:
        for i, r in enumerate(ex.map(one_run, jobs), 1):
            out.append(r)
            print(f"\r  {i}/{len(jobs)} runs", end="", flush=True)
    print()
    return pd.DataFrame(out)


def save(df, name):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, f"{name}.csv")
    df.to_csv(path, index=False)
    print(f"  -> {path}")


def ms(df, by, cols):
    """mean +/- std table (strings)."""
    m = df.groupby(by)[cols].mean()
    sd = df.groupby(by)[cols].std().fillna(0.0)
    out = m.copy().astype(object)
    for c in cols:
        out[c] = [f"{a:.3f} +/- {b:.3f}" for a, b in zip(m[c], sd[c])]
    return out


# ------------------------------------------------------------------ experiments
def centralized(seed):
    clients = make_clients(4, seed)
    X = np.vstack([c.Xtr for c in clients]); y = np.concatenate([c.ytr for c in clients])
    Xt, yt = global_test(clients)
    m = build(seed=seed)
    local_train(m, X, y, epochs=60, lr=0.05, seed=seed)
    return evaluate(m, Xt, yt)


def exp_privacy_utility(quick):
    """RQ1: accuracy vs epsilon (local DP vs distributed DP under SecAgg), plus the effect of #rounds."""
    T, seeds = (5, [0]) if quick else (5, range(8))
    eps_list = [2, 8] if quick else [1, 2, 4, 8, 16, 32]
    jobs = []
    for s in seeds:
        jobs.append(({"setting": "FedAvg (no DP)", "eps_target": np.inf, "rounds": T, "seed": s},
                     dict(rounds=T, dp="none", ledger=False, secagg=False, seed=s), {}))
        for mode in ("local", "distributed"):
            for e in eps_list:
                jobs.append(({"setting": f"{mode} DP", "eps_target": e, "rounds": T, "seed": s},
                             dict(rounds=T, dp=mode, z=noise_for_eps(e, T), ledger=False, secagg=False, seed=s), {}))
            for Tr in ([3, 10] if quick else [3, 5, 10, 20, 40]):      # communication rounds ablation at eps = 8
                if Tr != T:
                    jobs.append(({"setting": f"{mode} DP", "eps_target": 8, "rounds": Tr, "seed": s},
                                 dict(rounds=Tr, dp=mode, z=noise_for_eps(8, Tr), ledger=False, secagg=False, seed=s), {}))
    df = pmap(jobs)
    cent = pd.DataFrame([{**centralized(s), "setting": "centralized", "eps_target": np.inf, "rounds": 0, "seed": s} for s in seeds])
    df = pd.concat([df, cent], ignore_index=True)
    save(df, "privacy_utility")
    print(ms(df[df.rounds.isin([0, T])], ["setting", "eps_target"], ["acc", "auc"]).to_string())
    print(ms(df[df.eps_target == 8], ["setting", "rounds"], ["acc", "auc"]).to_string())


def exp_membership(quick):
    """RQ2: canary membership inference against an over-fit model, with and without client-level DP."""
    T, seeds = (8, [0]) if quick else (20, range(5))
    eps_list = [np.inf, 16] if quick else [np.inf, 256, 64, 16, 4]
    jobs = []
    for s, e in itertools.product(seeds, eps_list):
        kw = dict(rounds=T, hidden=64, local_epochs=30, lr_local=0.1, ledger=False, secagg=False, seed=s)
        if np.isinf(e):
            kw.update(dp="none", clip=0)
        else:
            kw.update(dp="distributed", clip=1.0, z=noise_for_eps(e, T))
        jobs.append(({"eps_target": e, "seed": s}, kw, {"canaries": 50}))
    df = pmap(jobs)
    save(df, "membership")
    print(ms(df, "eps_target", ["acc", "canary_auc", "canary_tpr@10%fpr"]).to_string())


def exp_attacks(quick):
    """RQ2: attack x defence matrix."""
    T, n, seeds = (6, 8, [0]) if quick else (10, 8, range(20))
    z = noise_for_eps(8, T)
    win = (3, 4, 5, 6)   # integrity attacks run in a window so the ability to recover is visible
    attacks = {
        "none": {},
        "poison: sign-flip x10": dict(malicious={3: "scale"}, attack_scale=10),
        "poison: label-flip (2 clients)": dict(malicious={3: "labelflip", 5: "labelflip"}),
        "stealth poison (forged input)": dict(malicious={3: "forge"}, attack_scale=10, attack_rounds=win),
        "missing DP noise (under-report)": dict(malicious={3: "noeps"}),
        "over-budget declaration": dict(malicious={3: "overbudget"}, eps_max=8.5),
        "server reverses aggregate": dict(server_attack="swap_aggregate", attack_rounds=win),
        "server drops a client": dict(server_attack="drop_client", attack_rounds=win),
    }
    defences = {
        "FedAvg+DP+SecAgg (no ledger)": dict(ledger=False, secagg=True),
        "ours, audit 25%": dict(ledger=True, secagg=True, audit_rate=0.25),
        "ours, audit 50%": dict(ledger=True, secagg=True, audit_rate=0.5),
    }
    jobs = []
    for (an, ak), (dn, dk), s in itertools.product(attacks.items(), defences.items(), seeds):
        kw = dict(rounds=T, n_clients=n, dp="distributed", z=z, seed=s)
        kw.update(ak); kw.update(dk)
        jobs.append(({"attack": an, "defence": dn, "seed": s}, kw, {}))
    df = pmap(jobs)
    df["detected"] = ((df.n_events > 0) | (df.refused_events > 0) | (df.banned.fillna("") != "")).astype(int)
    save(df, "attacks")
    print(df.groupby(["attack", "defence"])[["acc", "detected", "rejected_rounds", "first_event_round"]].mean().round(2).to_string())


def exp_overhead(quick):
    """RQ3: cost of each layer vs number of clients."""
    ns, T = ([4, 8], 3) if quick else ([4, 8, 16, 32], 5)
    variants = {
        "FedAvg": dict(dp="none", secagg=False, ledger=False),
        "+DP": dict(dp="distributed", secagg=False, ledger=False),
        "+DP+SecAgg": dict(dp="distributed", secagg=True, ledger=False),
        "+DP+SecAgg+Ledger (full)": dict(dp="distributed", secagg=True, ledger=True, audit_rate=0.25),
    }
    jobs = []
    for n, (vn, vk) in itertools.product(ns, variants.items()):
        jobs.append(({"clients": n, "variant": vn}, dict(rounds=T, n_clients=n, z=2.0, seed=0, **vk), {"warmup": True}))
    df = pmap(jobs, workers=2)       # few workers: we are timing things
    df["time_per_round_s"] = df[[c for c in df.columns if c.startswith("t_")]].sum(axis=1)
    df["bytes_per_client_round"] = df[[c for c in df.columns if c.startswith("bytes_")]].sum(axis=1) / df["clients"]
    save(df, "overhead")
    print(df[["clients", "variant", "time_per_round_s", "bytes_per_client_round", "gas_per_round", "acc"]].round(2).to_string(index=False))


def exp_audit_tradeoff(quick):
    """RQ2/4: audit rate vs detection latency, damage and privacy exposure; seeded vs statistical audits."""
    T, n, seeds = (6, 8, [0]) if quick else (15, 8, range(20))
    rates = [0.0, 0.5] if quick else [0.0, 0.1, 0.25, 0.5, 1.0]
    z = noise_for_eps(8, T)
    jobs = []
    for rate, s in itertools.product(rates, seeds):
        for mode in ("seeded", "statistical"):
            for atk, kw in (("sign-flip x10", dict(malicious={3: "scale"}, attack_scale=10)),
                            ("no DP noise", dict(malicious={3: "noeps"}))):
                jobs.append(({"attacker": atk, "audit_mode": mode, "audit_rate": rate, "seed": s},
                             dict(rounds=T, n_clients=n, z=z, audit_rate=rate, audit_mode=mode, emergency_audit=False,
                                  seed=s, **kw), {}))
    df = pmap(jobs)
    df["caught"] = (df.banned.fillna("") != "").astype(int)
    save(df, "audit_tradeoff")
    print(df.groupby(["attacker", "audit_mode", "audit_rate"])[["acc", "caught", "first_event_round", "honest_exposure"]]
          .mean().round(3).to_string())


def exp_dropout(quick):
    n, T, seeds = (8, 5, [0]) if quick else (16, 10, range(3))
    rates = [0.0, 0.3] if quick else [0.0, 0.1, 0.2, 0.3, 0.4]
    z = noise_for_eps(8, T)
    jobs = [({"dropout": p, "seed": s}, dict(rounds=T, n_clients=n, z=z, dropout=p, seed=s), {})
            for p, s in itertools.product(rates, seeds)]
    df = pmap(jobs)
    save(df, "dropout")
    print(df.groupby("dropout")[["acc", "accepted_rounds", "eps_max", "t_aggregate"]].mean().round(3).to_string())


def exp_chain_overhead(quick):
    """RQ3 on the REAL chain: measured gas / transactions / latency per round vs number of hospitals.
    Runs sequentially in-process (a single local node), and checks on-chain epsilon against the analytic accountant."""
    ns, T = ([4, 8], 3) if quick else ([4, 8, 16, 32], 5)
    rows = []
    for n in ns:
        z = noise_for_eps(8, T)
        f = Federation(Config(rounds=T, n_clients=n, z=z, chain="evm", seed=0))
        t0 = time.time()
        res = f.run()
        wall = time.time() - t0
        ct = f.contract
        txs = [t for t in ct.tx_log if t["method"] != "register"]
        rows.append({"clients": n, "rounds": T, "transactions": len(ct.tx_log),
                     "tx_per_round": len(txs) / T, "gas_per_round": sum(t["gas"] for t in txs) / T,
                     "max_single_tx_gas": max(t["gas"] for t in ct.tx_log), "deploy_gas": ct.gas_by_method["deploy"],
                     "seconds_per_round": wall / T, "eps_on_chain": max(res["eps"].values()),
                     "eps_analytic": eps_for(z, T), "acc": res["final"]["acc"]})
        print(f"  n={n}: {rows[-1]['tx_per_round']:.0f} tx/round, {rows[-1]['gas_per_round'] / 1e6:.2f}M gas/round, "
              f"{rows[-1]['seconds_per_round']:.1f}s/round")
    df = pd.DataFrame(rows)
    save(df, "chain_overhead")
    print(df.round(3).to_string(index=False))


def exp_adaptive(quick):
    """Item 1/9: audit policies vs poisoning, including a sleeper attacker. Fixed audits vs validation gate vs ZK norm proofs."""
    T, n = (6, 8) if quick else (10, 8)
    seeds = [0] if quick else range(16)
    z = noise_for_eps(8, T)
    base = dict(rounds=T, n_clients=n, z=z)
    policies = {
        "no defence (DP+SecAgg)": dict(ledger=False),
        "audit 25% only": dict(audit_rate=0.25),
        "audit 25% + validation gate": dict(audit_rate=0.25, val_gate=True),
        "audit 10% + validation gate": dict(audit_rate=0.10, val_gate=True),
        "ZK norm proofs (audit 0%)": dict(audit_rate=0.0, norm_proof="zk"),
    }
    scen = {
        "honest": {},
        "persistent sign-flip x10": dict(malicious={3: "scale"}, attack_scale=10),
        "sleeper sign-flip (rounds 5-9)": dict(malicious={3: "scale"}, attack_scale=10, attack_rounds=(5, 6, 7, 8, 9)),
    }
    jobs = []
    for (pn, pk), (sn, sk), sd in itertools.product(policies.items(), scen.items(), seeds):
        if "zk" in pk.get("norm_proof", "") and sd >= (1 if quick else 8):      # ZK runs are ~10x slower: fewer seeds
            continue
        jobs.append(({"policy": pn, "scenario": sn, "seed": sd}, {**base, **pk, **sk, "seed": sd}, {}))
    df = pmap(jobs)
    df["caught"] = (df.banned.fillna("") != "").astype(int)
    save(df, "adaptive_audit")
    print(df.groupby(["scenario", "policy"]).agg(acc=("acc", "mean"), sd=("acc", "std"), caught=("caught", "mean"),
                                                 rejected=("rejected_rounds", "mean"), emergency=("emergency_rounds", "mean"),
                                                 n=("seed", "count")).round(3).to_string())


def exp_baselines(quick):
    """Item 2: robust-aggregation baselines vs our system on the same attacks. Baselines see individual updates (no SecAgg)."""
    T, n = (6, 8) if quick else (10, 8)
    seeds = [0] if quick else range(16)
    z = noise_for_eps(8, T)
    attacks = {
        "honest": {},
        "sign-flip x10": dict(malicious={3: "scale"}, attack_scale=10),
        "sign-flip x1 (inside the bound)": dict(malicious={3: "scale"}, attack_scale=1),
        "label-flip (2 clients)": dict(malicious={3: "labelflip", 5: "labelflip"}),
        "sleeper sign-flip x10": dict(malicious={3: "scale"}, attack_scale=10, attack_rounds=(5, 6, 7, 8, 9)),
    }
    systems = {
        "FedAvg (mean)": dict(aggregator="mean", dp="none", ledger=False, secagg=False),
        "coord. median": dict(aggregator="median", dp="none", ledger=False, secagg=False),
        "trimmed mean": dict(aggregator="trimmed", dp="none", ledger=False, secagg=False),
        "Krum": dict(aggregator="krum", dp="none", ledger=False, secagg=False),
        "Multi-Krum": dict(aggregator="multikrum", dp="none", ledger=False, secagg=False),
        "ours (SecAgg + DP + ledger + gate)": dict(dp="distributed", z=z, ledger=True, secagg=True, val_gate=True,
                                                  audit_rate=0.25),
    }
    jobs = []
    for (an, ak), (sn, sk), sd in itertools.product(attacks.items(), systems.items(), seeds):
        kw = dict(rounds=T, n_clients=n, seed=sd, byz_f=len(ak.get("malicious", {})) or 1)
        kw.update(ak)
        kw.update(sk)
        jobs.append(({"attack": an, "system": sn, "seed": sd}, kw, {}))
    df = pmap(jobs)
    df["hides_updates_from_server"] = df.system.str.startswith("ours")
    save(df, "baselines")
    t = df.groupby(["system", "attack"]).acc.mean().unstack().round(3)
    print(t.to_string())


def exp_covtype(quick):
    """Item 3: a second, larger dataset (Forest Covertype, 4 wilderness areas, 20k rows) with an MLP (1665 parameters)."""
    T, seeds = (5, [0]) if quick else (20, range(4))
    eps_list = [8] if quick else [8, 32, np.inf]
    base = dict(dataset="covtype", hidden=32, rounds=T, local_epochs=5, lr_local=0.05, n_clients=4, ledger=False, secagg=False)
    jobs = []
    for sd in seeds:
        for mode in ("local", "distributed"):
            for e in eps_list:
                if np.isinf(e):
                    if mode == "local":
                        continue
                    jobs.append(({"setting": "no DP", "eps_target": e, "seed": sd}, dict(base, dp="none", clip=0, seed=sd), {}))
                else:
                    jobs.append(({"setting": f"{mode} DP", "eps_target": e, "seed": sd},
                                 dict(base, dp=mode, z=noise_for_eps(e, T), clip=1.0, seed=sd), {}))
        jobs.append(({"setting": "sign-flip, no defence", "eps_target": np.inf, "seed": sd},
                     dict(base, dp="none", clip=0.5, malicious={3: "scale"}, attack_scale=10, seed=sd), {}))
        jobs.append(({"setting": "sign-flip, audit 25% + gate", "eps_target": np.inf, "seed": sd},
                     dict(base, dp="none", clip=0.5, ledger=True, secagg=True, audit_rate=0.25, val_gate=True,
                          malicious={3: "scale"}, attack_scale=10, seed=sd), {}))
    df = pmap(jobs)
    save(df, "covtype")
    print(ms(df, ["setting", "eps_target"], ["acc", "auc"]).to_string())


def exp_zk_cost(quick):
    """Item 9: cost of the zero-knowledge norm proof vs model size (measured, single process)."""
    import random as _r
    from fedsec import zkproofs as zk
    from fedsec.pedersen import get_group
    G = get_group()
    SC = 2 ** 20
    clip = int(0.5 * SC)
    rows = []
    for d in ([14, 51] if quick else [14, 51, 128, 256]):
        B = zk.bound_for(clip, d)
        v = np.random.RandomState(0).normal(size=d)
        c = [int(round(x * SC)) for x in v / np.linalg.norm(v) * 0.4]
        t0 = time.time()
        proof, Cc, _ = zk.prove(G, c, B, b"ctx", rng=_r.Random(1))
        tp = time.time() - t0
        t0 = time.time()
        ok = zk.verify(G, proof, Cc, B, b"ctx")
        tv = time.time() - t0
        rows.append({"parameters": d, "prove_s": tp, "verify_s": tv, "proof_KB": zk.proof_size_bytes(proof, G) / 1024, "valid": ok})
    df = pd.DataFrame(rows)
    save(df, "zk_cost")
    print(df.round(3).to_string(index=False))


def exp_chain_backends(quick):
    """Item 6/7: the same federation on one Hardhat node and on a real 4-validator QBFT network, with the aggregate
    verified by the CONTRACT. Measured gas, transactions and latency per round. Sequential (single chain)."""
    ns, T = ([4], 2) if quick else ([4, 8], 3)
    rows = []
    for backend in ("evm", "besu"):
        for n in ns:
            f = Federation(Config(rounds=T, n_clients=n, z=noise_for_eps(8, T), chain=backend, onchain_verify=True,
                                  local_epochs=3, seed=0))
            t0 = time.time()
            res = f.run()
            wall = time.time() - t0
            ct = f.contract
            vg = [t["gas"] for t in ct.tx_log if t["method"] == "verifyAggregate"]
            rows.append({"backend": "Hardhat (1 node)" if backend == "evm" else "Besu QBFT (4 validators)", "clients": n,
                         "rounds": T, "tx_per_round": (len(ct.tx_log) - n) / T,
                         "gas_per_round": sum(t["gas"] for t in ct.tx_log if t["method"] != "register") / T,
                         "verify_gas_per_round": float(np.mean(vg)), "seconds_per_round": wall / T,
                         "rejected": res["rejected_rounds"], "acc": res["final"]["acc"]})
            print(f"  {rows[-1]['backend']} n={n}: {rows[-1]['seconds_per_round']:.1f}s/round, {rows[-1]['gas_per_round'] / 1e6:.1f}M gas/round")
        if backend == "besu":
            f.contract.network.stop()
    df = pd.DataFrame(rows)
    save(df, "chain_backends")
    print(df.round(2).to_string(index=False))


def exp_distributed(quick):
    """Item 5: a real multi-process deployment (server + hospitals as separate OS processes), with and without a crash."""
    from fedsec.dist import launch
    rows = []
    for tag, drop in (("no crash", ""), ("hospital 2 crashes in round 1", "2:1")):
        res = launch.main(["--clients", "4" if quick else "5", "--rounds", "2" if quick else "4", "--epochs", "5", "--drop", drop,
                           "--port", "9150", "--out", os.path.join(RESULTS, "distributed_" + tag.split()[0])])
        for h in res["history"]:
            rows.append({"scenario": tag, "round": h["round"], "accepted": h["accepted"], "chain_verified": h.get("chain_verified"),
                         "survivors": len(h.get("survivors", [])), "dropped": len(h.get("dropped", [])), "acc": h.get("acc"),
                         "processes": res["processes"], "gas_total": res["gas_total"], "wall_seconds": res["wall_seconds"]})
    df = pd.DataFrame(rows)
    save(df, "distributed")
    print(df.round(3).to_string(index=False))


EXPS = {"privacy_utility": exp_privacy_utility, "membership": exp_membership, "attacks": exp_attacks, "overhead": exp_overhead,
        "audit_tradeoff": exp_audit_tradeoff, "dropout": exp_dropout, "chain_overhead": exp_chain_overhead,
        "adaptive": exp_adaptive, "baselines": exp_baselines, "covtype": exp_covtype, "zk_cost": exp_zk_cost,
        "chain_backends": exp_chain_backends, "distributed": exp_distributed}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("exp", choices=list(EXPS) + ["all"])
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    for name in (EXPS if a.exp == "all" else [a.exp]):
        print(f"== {name}")
        EXPS[name](a.quick)
