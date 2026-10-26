# Headline results (quote these) and the caveats that go with them

All numbers are means over seeds (± one standard deviation) from the experiments in `data/`; the file in brackets is the table that holds them.

## 1. Privacy costs little accuracy when the noise is split under secure aggregation  [T01, T02; F02, F11]
* At epsilon = 8 over 5 rounds on the four real hospital silos: **distributed DP 0.77** vs **local DP 0.67**, FedAvg without privacy **0.82**.
* At epsilon = 16: 0.80 vs 0.76; at epsilon = 32 the gap closes (0.81 vs 0.79).
* Under DP fewer rounds win: accuracy peaks at ~10 rounds (0.78) and falls to 0.71 at 40.
* *Caveat:* the advantage is clear from epsilon >= 4; at epsilon <= 2 the error bars overlap.

## 2. The model stops leaking who was in the training data  [T03; F03, F04]
* Planted-record attack AUC: **0.66 without DP -> 0.57 (eps 256) -> 0.53 (eps 64) -> 0.47 (eps 16)** (chance = 0.5).
* *Caveat:* on the real records the attack is near 0.5 even without DP (the model barely over-fits), so canaries are used.

## 3. The server sees nothing  [F05]
* Similarity between the server's copy and the true update: **1.00 without secure aggregation, 0.00 with it** (4, 8, 16 hospitals).

## 4. Every attack in the suite is detected or blocked, except the stated limit  [T04, T13, F06, F10, F22]
* Sign-flip poisoner: 0.33 undefended -> 0.79 defended.
* Stealth forger: 0.68-0.74 -> 0.79-0.80, server reversing the aggregate: 0.71 -> 0.80 (ablation, 8 seeds).
* Ablation (accuracy, honest / poisoner / forger / reversed aggregate / skipped noise): FedAvg 0.82/0.33/0.74/0.81/0.82 -> + DP + SecAgg 0.81/0.32/0.68/0.71/0.81 -> + ledger 0.81/0.65/0.79/0.80/0.81 -> + validation gate 0.79/0.78/0.80/0.80/0.81.
* Label flipping inside the norm bound is **not** detected (bounded by clipping only).

## 5. The weakest result is fixed: poisoning no longer depends on audit luck  [T05; F07, F08]
| defence (10 rounds, 8 hospitals, 16 seeds; ZK 8) | persistent poisoner | sleeper |
|---|---|---|
| none | 0.34 | 0.56 |
| random audits 25% | 0.71 ± 0.15 | 0.72 ± 0.10 |
| + validation gate | 0.79 ± 0.03 | 0.77 ± 0.06 |
| **ZK norm proofs, audits 0%** | **0.79 ± 0.03** | **0.80 ± 0.03** |
* ZK proofs are the best trade: top accuracy, **zero exposure of any hospital's data**; the gate exposes honest hospitals in ~30-50% of rounds.

## 6. Honest comparison with robust aggregation  [T06; F09]
* Multi-Krum 0.82, trimmed mean 0.81, median 0.81 under sign-flip x10 vs **ours 0.79**.
* *They require the server to see every individual update; ours hides all of them.* We do **not** claim better robustness.

## 7. Real blockchain, real consensus, real processes  [T09-T11, T17; F18, F19, F23, F24]
* Solidity contract on a **4-validator QBFT network**: 1 validator killed -> the federation still completes; 2 killed -> the chain halts (never forks).
* The **contract itself verifies the aggregate** against the on-chain commitments (~0.9-1.7M gas per round for 14 parameters).
* A **distributed run** (server + 5 hospital processes) survives a real hospital crash; the crashed hospital is charged less epsilon, the others more.
* Measured: 23-42 transactions and 4-7M gas per round for 4-8 hospitals; 14-19 s per round on QBFT (1 s blocks).

## 8. Caveats to state yourself before a reviewer does
* **Second dataset (Covertype, MLP, 4 clients):** DP at epsilon = 8 gives 0.58 vs 0.78 without DP; **no advantage of distributed over local DP** at that size  [T07, F20].
* **ZK proof cost is linear:** 0.3 s at 14 parameters, 2.9 s at 256, ~19 s at 1,665  [T08, F17].
* **Not implemented:** TEE audit (needs enclave hardware); Shapley rewards (need individual updates, hidden by secure aggregation; stake/slash/reward used instead); a ZK proof of noise sampling.
* **Single machine:** QBFT validators and the distributed processes share one computer; Docker files are untested.
* **Demo-sized cryptography** (1024-bit group); passive-secure aggregation against the server; the simulation uses seeded blinding factors.
