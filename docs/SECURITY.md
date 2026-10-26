# Threat model and security argument

This document states what each layer guarantees, under which assumptions, and what is **not** claimed. Every
property names the test or experiment that exercises it. Proof sketches are rigorous in structure but are not
machine-checked; the cryptographic parameters (1024-bit Schnorr group) are demo-sized.

## 1. System and parties

* **Hospitals** `u = 1..n`: each holds a private dataset and trains locally. A hospital is identified by a registered
  chain account (the registry is permissioned, so Sybil identities are out of scope).
* **Server** `S`: aggregates masked updates and posts results. Untrusted.
* **Auditor** `A`: a role that receives openings for audits and posts audit results. Trusted not to leak what it sees
  (see §5); *not* trusted for the norm bound when ZK proofs are on.
* **Chain** `L`: the `PrivacyLedger` contract on an EVM chain. Either one Hardhat node (execution only) or a 4-validator
  QBFT network (Besu).

Notation: `x_u = c_u + n_u` is hospital `u`'s released update, `c_u` its clipped clean update (`||c_u||_2 <= C`), `n_u`
its DP noise `N(0, sigma_u^2 I)`; `X = sum_{u in V} x_u` over the survivor set `V`; `Com` is the vector Pedersen
commitment.

## 2. Assumptions

| id | assumption |
|---|---|
| A1 | Discrete logarithm is hard in the commitment group; SHA-256/keccak are collision resistant and behave as random oracles (Fiat-Shamir). |
| A2 | X25519 DH, HKDF, AES-GCM and the SHAKE-based PRG are secure. |
| A3 | At least `t = floor(m/2)+1` of the `m` round participants are honest and online until reveals complete (SecAgg threshold). |
| A4 | At least `h` hospitals add the noise they declare (`h` = `honest_frac * n`, the accountant's assumption). |
| A5 | The chain is correct: with QBFT and `n_v = 4` validators, at most `f = 1` is faulty; a single Hardhat node is trusted. |
| A6 | The auditor does not collude with the server (§5). |
| A7 | Hospitals' chain keys are not compromised; the client registry is honest. |
| A8 | **Simulation only:** blinding factors come from a seeded RNG so that runs are repeatable. The distributed client uses `SystemRandom`. |

## 3. Adversaries

* **A-srv-priv**: honest-but-curious server (reads everything it is sent).
* **A-srv-mal**: malicious server (drops / swaps / forges aggregates, omits clients).
* **A-cli**: up to `f_c < t` malicious hospitals (poison, skip noise, forge inputs, misdeclare noise, lie about budget).
* **A-col**: the server colluding with up to `t-1` hospitals.
* **A-rewrite**: someone who edits history after the fact.

## 4. Guarantees

### G1 Update privacy against the server (SecAgg)
*Claim.* Against A-srv-priv, the server's view of round `r` is computationally independent of any individual `x_u`
beyond the sum `X` over the survivors, provided A2, A3 and that every honest client reveals, for each peer, only a
key share (dropped) **or** a self-mask share (surviving), never both (`SAClient.reveal` refuses).
*Sketch.* Each `y_u = x_u + PRG(b_u) + sum_v (+-) PRG(s_uv)`. With `< t` shares the server cannot reconstruct `b_u` or
`sk_u`, so `PRG(b_u)` masks `x_u` perfectly under PRG security; pair masks cancel only in the full sum (Bonawitz et al., CCS 2017).
*Not claimed.* Privacy against a **malicious** server that shows different survivor lists to different clients: the
full active-secure protocol needs an extra consistency round. The contract's `submitted` set is a public, common
survivor list that a client could consult before revealing; the distributed client currently takes the list from the
server. *Tests:* `test_secagg_exact_with_dropouts`, `test_secagg_changes_nothing_but_privacy`, `test_distributed_run_with_a_real_crash`.

### G2 Differential privacy of what is released
*Claim.* Under A4, one round releases `sum_u clip_C(.) + N(0, z^2 C^2 I)` with `z = sigma sqrt(h)/C`, a Gaussian
mechanism of L2 sensitivity `C` (add/remove one hospital). It is `(alpha, alpha/(2 z^2))`-RDP; `T` rounds compose by addition
and convert to `(eps, delta)` with `eps = min_alpha [ T alpha/(2z^2) + log1p(-1/alpha) - (log delta + log alpha)/(alpha-1) ]`.
The contract recomputes this on-chain in fixed point (32 orders; conservative, agrees with the analytic value to < 0.1%).
*Scope.* Client-level DP over the whole run, for the **aggregate** (and, with `noise_model=local`, for each individual
update). Dropped clients take their noise share with them, so effective `z` drops and the contract charges the real
cost (slide 24; `test_dropout_recovery`).
*Not claimed.* DP for the *model after post-processing with auxiliary data* beyond standard post-processing, and
privacy of the **audited** hospital's update from the auditor (§5).

### G3 Aggregate integrity (binding + homomorphism)
*Claim.* If `prod_u Com(x_u; r_u) = Com(X; sum r_u)` is accepted for survivor set `V`, then `X = sum_{u in V} x_u`
up to a negligible-probability event under A1.
*Sketch.* Pedersen is perfectly hiding and computationally binding. If `X != sum x_u` while the products are equal,
dividing the two sides gives a non-trivial relation `g^a prod h_i^{b_i} = 1`, i.e. a discrete-log relation among
independent generators. The blinding sum `sum r_u` travels through the masked channel, so it is public only in aggregate.
*Who checks.* Off-chain by anyone, or **by the contract itself** (`verifyAggregate`, 1024-bit modular arithmetic
built on the modexp precompile; the contract's verdict overrides the server's claim). *Tests:* `test_forged_masked_input_*`,
`test_contract_itself_rejects_swapped_aggregate_and_forged_input`, `test_lying_server_is_overridden_by_the_contract`,
`test_modmul_matches_python_on_random_and_edge_values`.

### G4 Survivor-set integrity
Each hospital that sends its masked vector calls `markSubmitted` from its own account (with the hash of what it sent).
`postAggregate` accepts only if the server's survivor list equals that set, so the server cannot silently omit or add
a hospital (`test_server_dropping_client_detected_by_survivor_check`).

### G5 Budget enforcement
Admission, `begin_round`, recomputes `eps_u + cost(declared sigma_u)` on-chain and refuses hospitals that would
exceed `eps_max`; a hospital cannot post an intent whose sigma differs from the admitted one.
*Soundness limit.* The contract enforces the **declared** noise. Whether the hospital then adds exactly that noise is
checked by the seeded audit (G7) for the audited fraction of rounds only. A hospital that under-adds noise is caught in a given
round with probability `p` (audit rate), so by round `T` with probability `1-(1-p)^T`
(`audit_tradeoff.csv`). *Tests:* `test_privacy_budget_enforced_*`, `test_under_declared_noise_is_refused`.

### G6 Bounded influence of a client (ZK norm proof)
*Claim.* With `norm_proof = "zk"`, an accepted proof for hospital `u` in round `r` implies `||c_u||_2^2 <= B` where
`B = (C*2^20 + sqrt(d) + 1)^2` (fixed-point rounding slack), under A1 in the random-oracle model; the proof reveals
nothing about `c_u` beyond that fact (honest-verifier zero knowledge, made non-interactive by Fiat-Shamir).
*Sketch.* Per-coordinate Sigma proofs show `Q_i` commits to `a_i^2` where `P_i` commits to `a_i`; the product of the
`Q_i` commits to `sum a_i^2`; a bit-decomposition range proof shows the slack `w = B - sum a_i^2` lies in `[0, 2^k)`, so
`sum a_i^2 = B - w <= B`. Each bit is proven to be 0 or 1 by a Schnorr OR-proof; the bits recompose to the slack
commitment, which fixes `w`. Because the range is below the group order, there is no modular wrap-around.
*Consequence.* A coalition of `m` malicious hospitals can shift the aggregate by at most `m C` per round (a norm bound,
checked **every round for every hospital**, deterministically; contrast with sampled audits).
*Not claimed.* (i) Noise correctness is not proven (a ZK proof of Gaussian sampling from a committed seed is open),
so it stays with the seeded audit. (ii) A norm-bounded attacker (e.g. label flipping inside `C`) is not detected.
*Tests:* `tests/test_zk.py`, `test_zk_norm_proof_bans_poisoner_with_zero_audit_rate`.

### G7 Noise audit (verifiable noise)
A hospital commits to a seed (`sha256(seed)`) *before* the beacon `keccak(revealed nonces)` exists, and its noise is
`N(0, sigma^2)` from `H(seed || beacon)`. Under random-oracle assumptions it cannot grind for favourable noise. An audit
opens the seed; in `zk` mode the auditor checks that `Com_n` opens to the regenerated noise and that `Com_x = Com_c * Com_n`,
so it learns the **noise** but not the update; in `seeded` mode it recomputes `x - noise` and so learns the clean update.
Audit selection `keccak(beacon || Merkle root)` is fixed only after every commitment is posted, so no party controls it alone.

### G8 Tamper evidence
Blocks are hash-linked; with QBFT and at most `f=1` of 4 validators faulty, finalised history cannot be rewritten, and
with 2 down the chain halts rather than forks (`test_federation_survives_a_dead_validator_and_chain_halts_safely_with_two`).
A single Hardhat node gives hash linking but a node operator can rewrite their own chain. The Python-side record is also
re-checked against the node (`test_history_tampering_detected`).

### G9 Attribution and liveness
After a failed aggregate check the **blame phase** has survivors reveal mask seeds and commitment openings to the
auditor only. If `y_u - mask_u != opening` the forger is identified and banned (liveness restored after one rejected
round); if all hospitals are consistent but the published aggregate is not their sum, the **server** is blamed (and its
bond slashed). *Cost:* one round of exposure of every survivor's (noisy) update to the auditor. *Tests:*
`test_blame_phase_*`, `test_server_blamed_and_slashed`.

### G10 Quality gate (defence in depth)
A small public validation set lets the server reject any round that raises validation loss by more than `tau`
and trigger an emergency audit; it catches *sleeper* attackers and anything the norm check misses. It assumes the server
(or a regulator) holds such a set. It produced no false alarms on honest runs in the experiments.

## 5. Trust, collusion and exposure (the honest list)

* **Auditor.** In `zk` mode it learns noise only; in `seeded` and emergency/blame modes it learns noisy or clean
  updates of the opened hospitals. It must not collude with the server: server + auditor can subtract a revealed noise
  from the aggregate, weakening DP for that round by one share. Exposure is measured (`honest_exposure`) and equals the audit rate.
* **Collusion.** With `>= t` colluding hospitals SecAgg privacy can fail (A3). A coalition of `n-h` hospitals that skip
  their noise breaks A4 unless audited.
* **Label flipping inside the bound, and any model-poisoning that stays within `C`,** is not detectable by norm checks;
  its influence is bounded, not eliminated. Robust aggregators (Krum, median, trimmed mean) handle some of it but
  require seeing individual updates and so cannot run under SecAgg (compared in `experiments`).
* **Server availability.** A malicious server can refuse to post; the system fails safe (no bad model is accepted) but
  not live. A backup aggregator is future work.
* **Single local chain node.** Hardhat gives execution and signatures, not consensus; the QBFT backend does.
* **Cryptographic parameters** are demo-sized; production needs >= 3072-bit groups or an elliptic-curve instantiation.

## 6. Property -> mechanism -> evidence

| property | mechanism | evidence |
|---|---|---|
| server cannot read an update | SecAgg masks + Shamir recovery | G1 tests; slide 19 (similarity 1.00 -> 0.02) |
| released model is DP | clip + shared Gaussian noise + RDP accountant | G2; `privacy_utility.csv`; canary MIA (`membership.csv`) |
| aggregate is the true sum | Pedersen homomorphism, on-chain check | G3 tests; `chainVerified` |
| server cannot drop a hospital | `markSubmitted` set | G4 test |
| budgets are enforced | on-chain accountant at admission | G5 tests |
| poisoner cannot exceed norm `C` | ZK norm proof every round | G6 tests; `adaptive_audit.csv`, `zk_cost.csv` |
| cheater on noise is caught | seeded noise audit | G7 tests; `audit_tradeoff.csv` |
| history cannot be rewritten | hash chain / QBFT | G8 tests |
| forger identified, server blamed | blame phase | G9 tests |
| sleeper / unforeseen poisoning | validation gate + emergency audit | G10; `adaptive_audit.csv` |
