"""Attack demo: runs every attack against an undefended baseline and against the full system.

    python demo_attacks.py            # simulated ledger (fast)
    python demo_attacks.py evm        # the SAME attacks against the real Solidity contract on a local EVM chain
    # prints a table and writes results/demo_attacks.md (or demo_attacks_evm.md)

"Undefended" = FedAvg + DP + SecAgg with no ledger / commitments / audits.
"Defended"   = the full system.
"""
import os, sys, warnings

import numpy as np

warnings.filterwarnings("ignore")
from fedsec.accountant import noise_for_eps
from fedsec.federation import Config, Federation

CHAIN = "evm" if "evm" in sys.argv[1:] else "sim"
T, N, SEED = 10, 8, 0
Z = noise_for_eps(8, T)
WIN = (3, 4, 5, 6)
BASE = dict(rounds=T, n_clients=N, dp="distributed", z=Z, seed=SEED, chain=CHAIN)


def go(**kw):
    f = Federation(Config(**{**BASE, **kw}))
    return f, f.run()


def kinds(res):
    out = {}
    for e in res["events"]:
        out[e["type"]] = out.get(e["type"], 0) + 1
    return out


def row(name, what, und, dfn, verdict):
    return {"attack": name, "what the attacker does": what, "undefended": und, "defended": dfn, "verdict": verdict}


rows = []
clean_f, clean = go()
base_acc = clean["final"]["acc"]
und_kw = dict(ledger=False, secagg=True)   # undefended baseline never touches the chain


def acc(res):
    return f"acc {res['final']['acc']:.2f}"


# 1. server snooping on a hospital's update -------------------------------------------------
_, plain = go(secagg=False, ledger=False)
_, sec = go(secagg=True, ledger=False)
rows.append(row("Server reads a hospital's update", "honest-but-curious server inspects each submitted vector",
                f"similarity to true update = {plain['leak_cos']:.2f} (readable)",
                f"similarity = {sec['leak_cos']:+.2f} (looks random)",
                "BLOCKED by secure aggregation" if abs(sec["leak_cos"]) < 0.2 else "FAILED"))

# 2. poisoning -------------------------------------------------------------------------------
_, u = go(malicious={3: "scale"}, attack_scale=10, **und_kw)
f, d = go(malicious={3: "scale"}, attack_scale=10)
rows.append(row("Model poisoning (sign-flip, 10x boost)", "client 3 sends a reversed, oversized update",
                f"{acc(u)}  (clean {base_acc:.2f})",
                f"{acc(d)}; client 3 banned={3 in d['banned']}, first caught round {min([e['round'] for e in d['events'] if e['type']=='audit_fail'], default='-')}",
                "DETECTED + EXCLUDED" if 3 in d["banned"] else "MISSED"))

# 3. stealth poisoning via forged input -------------------------------------------------------
_, u = go(malicious={3: "forge"}, attack_scale=10, attack_rounds=WIN, **und_kw)
f, d = go(malicious={3: "forge"}, attack_scale=10, attack_rounds=WIN)
rows.append(row("Stealth poisoning (forged input)", "client 3 shows an honest update to auditors but sends a poisoned one",
                acc(u) + "  (silently accepted)",
                f"{acc(d)}; {d['rejected_rounds']} poisoned rounds rejected",
                "DETECTED (commitment check)" if d["rejected_rounds"] >= len(WIN) else "MISSED"))

# 4. malicious server reverses aggregate ------------------------------------------------------
_, u = go(server_attack="swap_aggregate", attack_rounds=WIN, **und_kw)
f, d = go(server_attack="swap_aggregate", attack_rounds=WIN)
rows.append(row("Server tampers with the aggregate", "server reverses the summed update before publishing",
                acc(u) + "  (silently accepted)",
                f"{acc(d)}; {d['rejected_rounds']} rounds rejected",
                "DETECTED (commitment check)" if d["rejected_rounds"] >= len(WIN) else "MISSED"))

# 5. malicious server drops a hospital --------------------------------------------------------
_, u = go(server_attack="drop_client", attack_rounds=WIN, **und_kw)
f, d = go(server_attack="drop_client", attack_rounds=WIN)
rows.append(row("Server silently drops a hospital", "server claims a live client vanished and excludes its data",
                acc(u) + "  (hospital ignored, nobody knows)",
                f"{acc(d)}; {kinds(d).get('survivor_mismatch', 0)} rounds flagged",
                "DETECTED (survivor check)" if kinds(d).get("survivor_mismatch") else "MISSED"))

# 6. missing DP noise -------------------------------------------------------------------------
f, d = go(malicious={3: "noeps"}, audit_rate=0.5)
rows.append(row("Client skips its DP noise", "client 3 declares noise but adds none (leaks its own data)",
                "undetectable (no way to check)",
                f"banned={3 in d['banned']}, caught round {min([e['round'] for e in d['events'] if e['type']=='audit_fail'], default='-')}",
                "DETECTED (seeded-noise audit)" if 3 in d["banned"] else "MISSED"))

# 7. dodging the privacy budget ---------------------------------------------------------------
f, d = go(malicious={3: "overbudget"}, eps_max=8.5)
refused = [e for e in d["events"] if e["type"] == "refused" and e["cid"] == 3]
rows.append(row("Client under-declares noise to dodge budget", "client 3 declares tiny noise to look cheap",
                "no budget enforcement",
                f"refused {len(refused)} times; spent eps = {d['eps'][3]:.1f}",
                "BLOCKED (contract admission)" if refused else "MISSED"))

# 8. ledger tampering -------------------------------------------------------------------------
f, d = go()
ok_before, _ = f.contract.verify_chain()
f.contract.blocks[3]["txs"][0]["args"]["round"] = 999
ok_after, bad = f.contract.verify_chain()
rows.append(row("Rewrite history on the ledger", "attacker edits a past transaction (e.g. a privacy-budget record)",
                "no audit trail to edit",
                f"chain valid before={ok_before}; after edit valid={ok_after}, broken at block {bad}",
                "DETECTED (hash chain)" if (ok_before and not ok_after) else "MISSED"))

# 9. model tampering --------------------------------------------------------------------------
f, d = go()
before = f.verify_model_history()
f.snapshots[4] = f.snapshots[4] + 1e-3
after = f.verify_model_history()
rows.append(row("Swap a stored model version", "attacker replaces a past global model (e.g. with a backdoored one)",
                "no way to tell",
                f"mismatching rounds before={before}, after={after}",
                "DETECTED (model-hash registry)" if (not before and after == [4]) else "MISSED"))

# 10. honest limitation -----------------------------------------------------------------------
_, u = go(malicious={3: "labelflip", 5: "labelflip"}, **und_kw)
f, d = go(malicious={3: "labelflip", 5: "labelflip"})
rows.append(row("Label-flipping (within norm bound)", "two clients train on flipped labels but respect the clip bound",
                acc(u), f"{acc(d)}; banned={d['banned']}",
                "NOT DETECTED - only bounded by clipping (known limitation)"))

# 11. poisoner with audits OFF: zero-knowledge norm proofs ----------------------------------------
_, u = go(malicious={3: "scale"}, attack_scale=10, **und_kw)
f, d = go(malicious={3: "scale"}, attack_scale=10, audit_rate=0.0, norm_proof="zk", rounds=5)
first = min([e["round"] for e in d["events"] if e["type"] == "audit_fail"], default="-")
rows.append(row("Poisoner, audits switched OFF (ZK proofs)", "client 3 sends an oversized update; nobody is ever audited",
                acc(u), f"{acc(d)}; banned={3 in d['banned']}, first caught round {first}",
                "DETECTED every round (ZK norm proof, no auditor)" if 3 in d["banned"] else "MISSED"))

# 12. sleeper poisoner: validation gate ---------------------------------------------------------
_, u = go(malicious={3: "scale"}, attack_scale=10, attack_rounds=(5, 6, 7, 8, 9), **und_kw)
f, d = go(malicious={3: "scale"}, attack_scale=10, attack_rounds=(5, 6, 7, 8, 9), val_gate=True)
rows.append(row("Sleeper poisoner (behaves for 5 rounds)", "client 3 is honest until round 5, then poisons",
                acc(u), f"{acc(d)}; banned={3 in d['banned']}; emergency audits={sum(h['emergency'] for h in d['history'])}",
                "DETECTED (audits + validation-gate backstop)" if 3 in d["banned"] else "PARTIAL"))

# 13. forger identified (blame phase) --------------------------------------------------------------
f, d = go(malicious={3: "forge"}, attack_scale=10, attack_rounds=(2, 3, 4, 5, 6, 7), audit_rate=0.0, attribution=True)
_, n = go(malicious={3: "forge"}, attack_scale=10, attack_rounds=(2, 3, 4, 5, 6, 7), audit_rate=0.0)
rows.append(row("Forger, stalls every round", "client 3 sends a poisoned vector but commits an honest one",
                f"{n['rejected_rounds']} rounds rejected, nobody identified",
                f"{d['rejected_rounds']} round rejected; banned={d['banned']}",
                "IDENTIFIED + BANNED (blame phase)" if d["banned"] == [3] else "MISSED"))

# ---------------------------------------------------------------------------------------------
cols = ["attack", "what the attacker does", "undefended", "defended", "verdict"]
w = {c: max(len(c), max(len(r[c]) for r in rows)) for c in cols}
w = {c: min(v, 46) for c, v in w.items()}


def wrap(s, n):
    words, lines, cur = s.split(), [], ""
    for x in words:
        if len(cur) + len(x) + 1 > n:
            lines.append(cur)
            cur = x
        else:
            cur = (cur + " " + x).strip()
    return lines + [cur]


backend_name = "REAL Solidity contract on a local EVM chain" if CHAIN == "evm" else "simulated Python ledger"
print(f"\nLedger backend: {backend_name}")
print(f"Clean run accuracy: {base_acc:.2f}   (n={N} clients, {T} rounds, eps<=8)\n")
for i, r in enumerate(rows, 1):
    print(f"[{i}] {r['attack']}")
    print(f"    attack    : {r['what the attacker does']}")
    print(f"    undefended: {r['undefended']}")
    print(f"    defended  : {r['defended']}")
    print(f"    => {r['verdict']}\n")

os.makedirs("results", exist_ok=True)
out = "demo_attacks_evm.md" if CHAIN == "evm" else "demo_attacks.md"
with open(os.path.join("results", out), "w", encoding="utf-8") as fh:
    fh.write(f"# Attack demo - {backend_name} (clean accuracy {base_acc:.2f}; n={N}, {T} rounds, eps<=8)\n\n")
    fh.write("| attack | what the attacker does | undefended | defended | verdict |\n|---|---|---|---|---|\n")
    for r in rows:
        fh.write("| " + " | ".join(r[c].replace("|", "/") for c in cols) + " |\n")
print("written results/" + out)
