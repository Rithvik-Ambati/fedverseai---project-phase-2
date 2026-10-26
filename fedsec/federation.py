"""The federation: clients, DP noise, secure aggregation, commitments, audits, ledger.

One round
  1. contract admits clients whose privacy budget still covers the planned noise
  2. each client trains locally, clips its update to norm C and adds its share of DP noise
  3. each client posts a Pedersen commitment to its (fixed-point) update + its declared sigma;
     the contract Merkle-ises them and runs commit-reveal randomness to pick audits
  4. audited clients open their commitment to the auditor, who checks clip bound and that the
     declared noise is actually present; failures hit reputation and are excluded
  5. secure aggregation (masks + dropout recovery); the blinding factors travel through the
     same masked channel so the sum of blindings is public
  6. anyone verifies  prod C_u == Com(aggregate; sum r_u)  => the aggregate is exactly the sum
     of the committed updates (no drop / swap / forgery by the server)
  7. aggregate-norm gate: if the sum is implausibly large, an emergency audit opens every update
  8. contract records the model hash, charges everyone's privacy budget
"""
import contextlib, copy, hashlib, math, random, time
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

from .accountant import RDPAccountant
from .data import global_test, global_val, make_clients
from .ledger import PrivacyContract
from .model import build, evaluate, get_flat, local_train, n_params, per_sample_loss, set_flat
from .pedersen import get_group
from .robust import aggregate as robust_aggregate
from . import zkproofs as zk
from .secagg import secure_aggregate

SCALE = 2 ** 20


@dataclass
class Config:
    n_clients: int = 4
    rounds: int = 20
    local_epochs: int = 15
    lr_local: float = 0.05
    server_lr: float = 1.0
    hidden: int = 0                  # 0 = logistic regression (best utility under client-level DP)
    clip: float = 0.5
    dp: str = "distributed"          # "none" | "local" | "distributed"
    z: float = 1.0                   # target aggregate noise multiplier
    delta: float = 1e-5
    honest_frac: float = 1.0         # fraction of clients assumed honest when splitting noise
    secagg: bool = True
    ledger: bool = True              # commitments + contract + audits
    audit_rate: float = 0.25
    emergency_audit: bool = True
    stake: float = 0.0               # evm only: ETH each hospital (and the server) stakes; failed audits are slashed
    slash: float = 0.4               # ETH slashed per failed audit (a ban forfeits the rest)
    attribution: bool = False        # after a failed commitment check run the blame phase: ban the forger / blame the server
    onchain_verify: bool = False     # evm only: the CONTRACT checks the aggregate against the commitments (small models)
    norm_proof: str = "none"         # "zk": every client proves ||clean update||_2 <= clip in zero knowledge, every round;
                                     # the noise audit then reveals only the noise seed, never the update
    dataset: str = "heart"           # "heart" (4 hospitals, 920 patients) | "covtype" (4 wilderness areas, 20k rows)
    aggregator: str = "mean"         # mean | median | trimmed | krum | multikrum (robust ones need secagg=False)
    byz_f: int = 1                   # assumed Byzantine clients for krum / multikrum
    val_gate: bool = False           # server holds a small public validation set; a round that worsens it is rolled back
    val_tau: float = 0.12            # tolerated increase of validation loss per round (DP noise headroom)
    val_frac: float = 0.08           # share of each silo's train data held out as the public validation set
    probation_rounds: int = 0        # audit at `probation_rate` during the first rounds
    probation_rate: float = 1.0
    boost_rounds: int = 3            # after a gate alarm, audit at `boost_rate` for this many rounds
    boost_rate: float = 1.0
    audit_mode: str = "seeded"       # seeded: auditor recomputes the exact noise (and so sees the clean update)
                                     # statistical: auditor sees only the noisy update; chi-square tests, needs large d
    eps_max: float = float("inf")
    eps_max_per_client: dict = field(default_factory=dict)
    dropout: float = 0.0
    malicious: dict = field(default_factory=dict)   # cid -> scale|labelflip|noeps|overbudget|forge
    attack_scale: float = 10.0
    chain: str = "sim"               # "sim" = simulated Python ledger | "evm" = Solidity contract on one local Hardhat node |
                                     # "besu" = same contract on a real 4-validator QBFT (BFT consensus) network
    attack_rounds: tuple = ()        # () => client attacks active every round
    server_attack: str = ""          # "" | swap_aggregate | drop_client
    server_attack_rounds: tuple = ()  # () => every round
    seed: int = 0


# ---------------------------------------------------------------- helpers
def signed(v, q):
    return v if v <= q // 2 else v - q


def encode(x, q):
    return [int(round(v * SCALE)) % q for v in x]


def decode(v, q):
    return np.array([(a - q if a > q // 2 else a) / SCALE for a in v], dtype=np.float64)


def model_hash(w):
    return hashlib.sha256(np.asarray(w, dtype=np.float32).tobytes()).hexdigest()


def plausible(x_norm_sq, n_terms_sigma_sq, d, sig_bound, max_clean_norm):
    """Chi-square style 4-sigma window for ||clean + N(0, s^2 I)||^2.
    Returns (upper_ok, lower_ok)."""
    s2 = n_terms_sigma_sq
    s = math.sqrt(s2)
    spread = 4 * s2 * math.sqrt(2 * d) + 8 * s * max_clean_norm
    upper = max_clean_norm ** 2 + d * s2 + spread
    lower = d * s2 - 4 * s2 * math.sqrt(2 * d) - 8 * s * max_clean_norm
    return x_norm_sq <= upper, x_norm_sq >= lower


def check_update(x, sigma, clip, d):
    """Auditor test on an opened update: respects the clip bound and carries the declared noise."""
    n2 = float(np.dot(x, x))
    up, lo = plausible(n2, sigma ** 2, d, sigma, clip)
    if not up:
        return False, "norm bound violated"
    if sigma > 0 and not lo:
        return False, "declared noise missing"
    return True, ""


def noise_vec(seed: bytes, beacon: bytes, sigma: float, d: int):
    """Deterministic Gaussian noise derived from the committed seed and the later public beacon, so an
    auditor can regenerate it exactly and the client cannot grind for favourable noise."""
    s = int.from_bytes(hashlib.sha256(b"noise" + seed + beacon).digest()[:8], "big")
    return np.random.default_rng(s).normal(0.0, sigma, d)


def check_seeded(x, seed, seed_hash, beacon, sigma, clip, d):
    if hashlib.sha256(seed).hexdigest() != seed_hash:
        return False, "seed does not match commitment"
    clean = x - noise_vec(seed, beacon, sigma, d)
    if float(np.linalg.norm(clean)) > clip * (1 + 1e-4) + 1e-3:
        return False, "clean update violates norm bound / declared noise absent"
    return True, ""


def make_ledger(cfg):
    if cfg.chain == "besu":
        from .besunet import BesuNetwork
        from .evmchain import EVMChain
        net = BesuNetwork.shared().start()
        c = EVMChain(cfg.delta, cfg.audit_rate, cfg.n_clients, min_stake=cfg.stake, slash=cfg.slash,
                     rpc=net.rpc(0), local_signing=True)
        c.network = net
        return c
    if cfg.chain == "evm":
        from .evmchain import EVMChain
        return EVMChain(cfg.delta, cfg.audit_rate, cfg.n_clients, min_stake=cfg.stake, slash=cfg.slash)
    return PrivacyContract(cfg.delta)


class Federation:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        if cfg.aggregator != "mean" and cfg.secagg:
            raise ValueError("robust aggregators inspect individual updates and cannot be combined with secagg=True")
        self.clients = make_clients(cfg.n_clients, cfg.seed, val_frac=cfg.val_frac if cfg.val_gate else 0.0,
                                    dataset=cfg.dataset)
        self.Xte, self.yte = global_test(self.clients)
        self.model = build(n_in=self.clients[0].Xtr.shape[1], hidden=cfg.hidden, seed=cfg.seed)
        self.work = copy.deepcopy(self.model)
        self.d = n_params(self.model)
        self.G = get_group()
        self.q = self.G.q
        self.np_rng = np.random.RandomState(cfg.seed + 7)
        self.py_rng = random.Random(cfg.seed + 11)
        self.h = max(1, round(cfg.honest_frac * cfg.n_clients))
        self.timers = defaultdict(float)
        self.bytes = defaultdict(int)
        self.history, self.leak, self.exposure = [], [], defaultdict(int)
        self.snapshots = {}
        self.local_acct = {c.cid: RDPAccountant(cfg.delta) for c in self.clients}
        self.contract = None
        if cfg.ledger:
            self.contract = make_ledger(cfg)
            self.contract.set_honest_k(self.h)
            for c in self.clients:
                self.contract.register(c.cid, cfg.eps_max_per_client.get(c.cid, cfg.eps_max))
            if cfg.stake > 0 and getattr(self.contract, "backend", "sim") == "evm":
                for c in self.clients:
                    self.contract.deposit(c.cid, cfg.stake)
                self.contract.post_server_bond(cfg.stake)
            self.contract.seal("genesis")
        self.w = get_flat(self.model)
        self._boost_left = 0
        self._slashed_server = 0
        if cfg.val_gate:
            self.Xva, self.yva = global_val(self.clients)
            self._val_cur = self._val_loss(self.w)

    def _val_loss(self, w):
        set_flat(self.work, w)
        return float(per_sample_loss(self.work, self.Xva, self.yva).mean())

    def _audit_rate(self, r):
        rate = self.cfg.audit_rate
        if r < self.cfg.probation_rounds:
            rate = max(rate, self.cfg.probation_rate)
        if self._boost_left > 0:
            rate = max(rate, self.cfg.boost_rate)
            self._boost_left -= 1
        return rate

    def _batch(self):
        ct = self.contract
        return ct.batch() if ct is not None and hasattr(ct, "batch") else contextlib.nullcontext()

    # ---------------------------------------------------------- client side
    def _plan(self, n_cand):
        cfg = self.cfg
        if cfg.dp == "none":
            return 0.0, "local"
        if cfg.dp == "local":
            return cfg.z * cfg.clip, "local"
        return cfg.z * cfg.clip / math.sqrt(min(self.h, n_cand)), "distributed"

    def _atk(self, cid, r):
        a = self.cfg.malicious.get(cid, "")
        return a if (not self.cfg.attack_rounds or r in self.cfg.attack_rounds) else ""

    def _clean_update(self, c, r):
        """Local training + clipping (+ poisoning if this client is malicious this round)."""
        cfg = self.cfg
        atk = self._atk(c.cid, r)
        set_flat(self.work, self.w)
        local_train(self.work, c.Xtr, c.ytr, cfg.local_epochs, cfg.lr_local, seed=cfg.seed * 1000 + r * 10 + c.cid,
                    flip=(atk == "labelflip"))
        delta = get_flat(self.work) - self.w
        if cfg.clip > 0:
            delta = delta * min(1.0, cfg.clip / (np.linalg.norm(delta) + 1e-12))
        if atk == "scale":   # untargeted poisoning: opposite direction, norm boosted to attack_scale * C
            delta = -delta / (np.linalg.norm(delta) + 1e-12) * cfg.attack_scale * cfg.clip
        return delta

    def _audit(self, r, cid, enc_x, rr, seed, beacon, sigma):
        """Auditor-side check of an opened update. Returns (ok, reason)."""
        ct, cfg = self.contract, self.cfg
        rec = ct.rounds[r]["commit"][cid]
        self.exposure[cid] += 1
        if cfg.norm_proof == "zk":
            z = self._zk[cid]
            if hashlib.sha256(seed).hexdigest() != rec["seed_hash"]:
                return False, "seed does not match commitment"
            n_int = encode(noise_vec(seed, beacon, sigma, self.d), self.q) if sigma > 0 else [0] * self.d
            if not self.G.open_ok(z["Com_n"], n_int, z["r_n"]):
                return False, "declared noise absent / does not match committed noise"
            if (z["Com_c"] * z["Com_n"]) % self.G.p != int(rec["c"], 16):
                return False, "commitment inconsistent with noise + clean parts"
            return True, ""
        if not self.G.open_ok(int(rec["c"], 16), enc_x, rr):
            return False, "bad opening"
        x = decode(enc_x, self.q)
        if cfg.audit_mode == "seeded":
            return check_seeded(x, seed, rec["seed_hash"], beacon, sigma, cfg.clip, self.d)
        return check_update(x, sigma, cfg.clip, self.d)

    def _blame(self, r, res, enc, rr, declared, agg, vectors):
        """Blame phase after a failed aggregate check. Survivors reveal their mask seeds and commitment openings to
        the AUDITOR only (never the server). For each client the auditor recomputes  y_u - mask_u  and compares it with
        the opened commitment: a mismatch pins the forger. If every client is consistent but the server's published
        aggregate is not the sum of the openings, the server is at fault. Costs one round of exposure."""
        ct, q, d = self.contract, self.q, self.d
        L = len(res.masked[declared[0]])
        forgers = []
        for u in declared:
            mask = res.clients[u].mask_only(res.pubs, res.rnd, L, q)
            plain = [(y - m) % q for y, m in zip(res.masked[u], mask)]
            self.exposure[u] += 1
            if plain[:d] != enc[u] or plain[d] != rr[u]:
                forgers.append(u)
        for u in forgers:
            ct.report_audit(r, u, False, "forged masked input (blame phase)")
            ct._ev(r, "forger_identified", cid=u)
        if not forgers:
            true_sum = [sum(enc[u][i] for u in declared) % q for i in range(d)]
            if true_sum != list(agg[:d]):
                ct._ev(r, "server_blamed")
                self.server_blamed = getattr(self, "server_blamed", 0) + 1

    # ---------------------------------------------------------- one round
    def run_round(self, r):
        cfg, G, q, d = self.cfg, self.G, self.q, self.d
        ct = self.contract
        t = time.perf_counter
        rec = {"round": r, "rejected": False, "emergency": False}
        cids = [c.cid for c in self.clients]
        sigma, nm = self._plan(len(cids))
        plan = {cid: ((sigma / 20 if cfg.malicious.get(cid) == "overbudget" else sigma), cfg.clip, nm) for cid in cids}

        # 1. admission
        if ct:
            admitted, refused = ct.begin_round(r, cids, plan, min(self.h, len(cids)))
        else:
            admitted, refused = cids, {}
        rec["refused"] = refused
        if len(admitted) < 2:
            rec.update(rejected=True, reason="too few clients")
            self._finish_round(r, rec)
            return rec
        by_id = {c.cid: c for c in self.clients}

        # 2. client intent: declare sigma, commit to the noise seed and to a beacon contribution
        seeds, nonces, rr, enc, x, beacon = {}, {}, {}, {}, {}, b""
        noise_enc, clean_enc, self._zk = {}, {}, {}
        t0 = t()
        clean = {cid: self._clean_update(by_id[cid], r) for cid in admitted}
        self.timers["train"] += t() - t0
        for cid in admitted:
            seeds[cid] = self.py_rng.randbytes(16)
            nonces[cid] = self.py_rng.randbytes(16)
        if ct:
            with self._batch():
                for cid in admitted:
                    ct.post_intent(r, cid, plan[cid][0], cfg.clip, nm, hashlib.sha256(seeds[cid]).hexdigest(),
                                   hashlib.sha256(nonces[cid]).hexdigest())
            with self._batch():
                for cid in admitted:
                    ct.reveal_nonce(r, cid, nonces[cid])
            beacon = ct.beacon(r)

        # 3. noise from (seed, beacon); commit to the final update
        t0 = t()
        for cid in admitted:
            sig = plan[cid][0]
            skip = self._atk(cid, r) == "noeps" or sig <= 0
            noise = np.zeros(self.d) if skip else noise_vec(seeds[cid], beacon, sig, self.d)
            x[cid] = clean[cid] + noise
            if cfg.norm_proof == "zk":          # exact homomorphism: enc = enc(clean) + enc(noise)
                noise_enc[cid] = encode(noise, q)
                clean_enc[cid] = encode(clean[cid], q)
                enc[cid] = [(a + b) % q for a, b in zip(clean_enc[cid], noise_enc[cid])]
            else:
                enc[cid] = encode(x[cid], q)
        self.timers["noise"] += t() - t0
        if ct:
            t0 = t()
            B = zk.bound_for(int(round(cfg.clip * SCALE)), d) if cfg.norm_proof == "zk" else 0
            posts = {}
            for cid in admitted:
                if cfg.norm_proof == "zk":
                    tz = t()
                    ctx = f"{cfg.seed}|{r}|{cid}".encode()
                    proof, Com_c, r_c = zk.prove(G, [signed(v, q) for v in clean_enc[cid]], B, ctx, rng=self.py_rng)
                    r_n = self.py_rng.randrange(q)
                    Com_n = G.commit(noise_enc[cid], r_n)
                    self._zk[cid] = {"proof": proof, "Com_c": Com_c, "Com_n": Com_n, "r_n": r_n, "ctx": ctx,
                                     "B": B, "size": zk.proof_size_bytes(proof, G)}
                    rr[cid] = (r_c + r_n) % q
                    Com_x = (Com_c * Com_n) % G.p
                    self.timers["zk_prove"] += t() - tz
                    self.bytes["zk_proof"] += self._zk[cid]["size"]
                else:
                    rr[cid] = self.py_rng.randrange(q)   # seeded => runs are exactly repeatable (simulation)
                    Com_x = G.commit(enc[cid], rr[cid])
                posts[cid] = hex(Com_x)
                self.bytes["commit"] += 128
            with self._batch():
                for cid in admitted:
                    ct.post_commitment(r, cid, posts[cid])
            if cfg.norm_proof == "zk":
                with self._batch():
                    for cid in admitted:
                        z = self._zk[cid]
                        bundle = repr((z["Com_c"], z["Com_n"], z["proof"])).encode()
                        ct.post_proof(r, cid, hashlib.sha256(bundle).hexdigest())
            self.timers["commit"] += t() - t0
            ct.close_commitments(r)

            # 4. audits (opened to the auditor)
            zk_failed = []
            if cfg.norm_proof == "zk":              # ANYONE can run this check; no trusted auditor involved
                tv = t()
                for cid in admitted:
                    z = self._zk[cid]
                    if not zk.verify(G, z["proof"], z["Com_c"], z["B"], z["ctx"]):
                        zk_failed.append(cid)
                        ct.report_audit(r, cid, False, "zk norm proof invalid")
                self.timers["zk_verify"] += t() - tv
            t0 = t()
            audit_set = [c for c in ct.select_audits(r, self._audit_rate(r)) if c not in zk_failed]
            failed = list(zk_failed)
            for cid in audit_set:
                ok, why = self._audit(r, cid, enc[cid], rr[cid], seeds[cid], beacon, plan[cid][0])
                ct.report_audit(r, cid, ok, why)
                if not ok:
                    failed.append(cid)
            self.timers["audit"] += t() - t0
            rec["audited"], rec["audit_failed"] = audit_set, failed
            admitted = [c for c in admitted if c not in failed]
            ct.seal(f"round {r}: commit+audit")
            if len(admitted) < 2:
                rec.update(rejected=True, reason="too few clients after audit")
                self._finish_round(r, rec)
                return rec

        # 5. aggregation
        dropped = {cid for cid in admitted if self.py_rng.random() < cfg.dropout}
        vectors = {cid: enc[cid] + ([rr[cid]] if ct else []) for cid in admitted}
        for cid in admitted:
            if self._atk(cid, r) == "forge":           # commits/opens a benign update but sends a poisoned one
                bad = -clean[cid] / (np.linalg.norm(clean[cid]) + 1e-12) * cfg.attack_scale * cfg.clip
                vectors[cid] = encode(bad, q) + vectors[cid][d:]
        really_sent = [u for u in admitted if u not in dropped]
        active_server_atk = bool(cfg.server_attack) and (not (cfg.server_attack_rounds or cfg.attack_rounds) or r in (cfg.server_attack_rounds or cfg.attack_rounds))
        server_dropped = set(dropped)
        if active_server_atk and cfg.server_attack == "drop_client" and len(really_sent) > 1:
            server_dropped.add(really_sent[0])          # claims a live client vanished
        t0 = t()
        if cfg.secagg:
            res = secure_aggregate(vectors, admitted, server_dropped, r, q, seed=cfg.seed)
            self.bytes["secagg"] += res.bytes_up
            if res.aborted:
                rec.update(rejected=True, reason="secagg aborted (too many dropouts)")
                self._finish_round(r, rec)
                return rec
            agg, survivors, view = res.aggregate, res.survivors, res.masked
        else:
            survivors = [u for u in admitted if u not in server_dropped]
            agg = [sum(vectors[u][i] for u in survivors) % q for i in range(len(vectors[survivors[0]]))]
            view = {u: vectors[u] for u in survivors}
            self.bytes["plain"] += len(survivors) * len(agg) * 8
        self.timers["aggregate"] += t() - t0
        for u in survivors:   # server's-eye leakage: how well does its view correlate with the true update?
            a = decode(view[u][:d], q)
            b = decode(enc[u], q)
            self.leak.append(float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-30)))

        # 6. server behaviour + verification
        declared = list(survivors)
        if active_server_atk and cfg.server_attack == "swap_aggregate":   # server reverses the update direction
            agg = [(-a) % q for a in agg]
        verified = True
        if ct:
            t0 = t()
            with self._batch():
                for u in really_sent:
                    ct.submitted(r, u, hashlib.sha256(repr(view[u]).encode()).hexdigest() if u in view else "")
            Cs = [int(ct.rounds[r]["commit"][u]["c"], 16) for u in declared]
            verified = G.combine(Cs) == G.commit(agg[:d], agg[d])
            if cfg.onchain_verify and getattr(ct, "backend", "sim") == "evm":
                chain_ok = ct.verify_aggregate_onchain(r, declared, agg[:d], agg[d], G)
                assert chain_ok == verified, "on-chain and off-chain commitment checks disagree"
                verified = chain_ok
            self.timers["verify"] += t() - t0
            if not verified and cfg.attribution and cfg.secagg:
                self._blame(r, res, enc, rr, declared, agg, vectors)
        Xenc = list(agg[:d])
        X = decode(Xenc, q)
        survivors_final = list(declared)
        if cfg.aggregator != "mean" and survivors_final:       # robust baseline: server sees individual updates
            U = np.stack([decode(enc[u], q) for u in survivors_final])
            X = robust_aggregate(cfg.aggregator, U, f=cfg.byz_f) * len(survivors_final)
            Xenc = encode(X, q)

        # 7. gates: implausible aggregate norm and/or validation-loss regression => emergency audit + rollback
        def cand(Xv, n):
            return self.w + cfg.server_lr * Xv / max(1, n)

        emergency, val_trig, norm_bad = False, False, False
        if ct and verified and cfg.emergency_audit:
            s_tot2 = sum(plan[u][0] ** 2 for u in survivors_final)
            norm_bad = not plausible(float(np.dot(X, X)), s_tot2, d, math.sqrt(s_tot2), len(survivors_final) * cfg.clip)[0]
        if cfg.val_gate and verified and survivors_final:
            val_trig = self._val_loss(cand(X, len(survivors_final))) > self._val_cur + cfg.val_tau
        if ct and verified and cfg.emergency_audit and (norm_bad or val_trig):
            emergency = True
            t0 = t()
            good = []
            for u in survivors_final:
                ok, why = self._audit(r, u, enc[u], rr[u], seeds[u], beacon, plan[u][0])
                ct.report_audit(r, u, ok, why or "emergency audit")
                if ok:
                    good.append(u)
            self.timers["audit"] += t() - t0
            if good:
                Xenc = [sum(enc[u][i] for u in good) % q for i in range(d)]
                X = decode(Xenc, q)
            survivors_final = good
        gate_ok = True
        if cfg.val_gate and verified:
            gate_ok = bool(survivors_final) and self._val_loss(cand(X, len(survivors_final))) <= self._val_cur + cfg.val_tau
            if val_trig:
                self._boost_left = cfg.boost_rounds
        rec["emergency"] = emergency
        rec["gate_triggered"] = bool(val_trig or norm_bad)
        rec["n_included"] = len(survivors_final)

        # 8. apply + record
        accepted = True
        agg_hash = hashlib.sha256(repr(Xenc).encode()).hexdigest()
        wn = cand(X, len(survivors_final))
        if ct:
            accepted = ct.post_aggregate(r, declared, model_hash(wn), agg_hash, verified, emergency, gate_ok)
            if not accepted:
                rec["rejected"] = True
                rec["reason"] = ("aggregate verification failed" if not verified else
                                 "survivor set mismatch" if gate_ok else "validation gate")
        else:
            for u in survivors:
                z = PrivacyContract.noise_multiplier(plan[u][0], cfg.clip, nm, min(self.h, len(survivors)))
                if z > 0:
                    self.local_acct[u].add(z)
            if not gate_ok:
                accepted = False
                rec["rejected"], rec["reason"] = True, "validation gate"
        if accepted and survivors_final:
            self.w = wn
            set_flat(self.model, self.w)
            self.snapshots[r] = self.w.copy()
            if cfg.val_gate:
                self._val_cur = self._val_loss(self.w)
        if ct and cfg.stake > 0 and getattr(ct, "backend", "sim") == "evm" and not accepted and getattr(self, "server_blamed", 0) > self._slashed_server:
            ct.slash_server(r)
            self._slashed_server += 1
        if ct:
            ct.seal(f"round {r}: aggregate")
        self._finish_round(r, rec)
        return rec

    def eps(self, cid):
        return self.contract.epsilon(cid) if self.contract else self.local_acct[cid].eps()

    def _finish_round(self, r, rec):
        m = evaluate(self.model, self.Xte, self.yte)
        rec.update(m)
        rec["eps_max_spent"] = max(self.eps(c.cid) for c in self.clients)
        self.history.append(rec)

    def run(self):
        for r in range(self.cfg.rounds):
            self.run_round(r)
        return self.result()

    def result(self):
        final = self.history[-1] if self.history else {}
        out = {"cfg": self.cfg, "history": self.history, "final": final, "model": self.model,
               "timers": dict(self.timers), "bytes": dict(self.bytes),
               "leak_cos": float(np.mean(self.leak)) if self.leak else float("nan"),
               "eps": {c.cid: self.eps(c.cid) for c in self.clients},
               "exposure": dict(self.exposure), "clients": self.clients,
               "rejected_rounds": sum(1 for h in self.history if h.get("rejected")), "events": [], "banned": []}
        if self.contract:
            out.update(contract=self.contract, events=self.contract.events, gas=self.contract.gas_total,
                       gas_by_method=self.contract.gas_by_method,
                       banned=[c for c, v in self.contract.clients.items() if v["banned"]])
        return out

    def verify_model_history(self):
        """Recompute hashes of stored snapshots and compare with what the contract recorded."""
        bad = []
        for r, w in self.snapshots.items():
            if self.contract.models.get(r) != model_hash(w):
                bad.append(r)
        return bad
