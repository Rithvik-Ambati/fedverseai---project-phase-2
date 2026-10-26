"""Permissioned hash-chained ledger + 'smart contract' rules.

This is a *simulated* chain (pure Python) so the whole system runs offline and
deterministically. Every contract method is a transaction recorded in a block; blocks are
hash-linked, so editing any historic transaction breaks `verify_chain()`.
The rules are written so they can be ported to Solidity 1:1 (see README); gas numbers are
a rough EVM-style estimate (21k base + calldata + 20k per fresh 32-byte storage word).

Contract responsibilities
  * client registry with a per-client privacy budget eps_max
  * privacy-budget accountant: recomputes every client's epsilon from the *declared* noise
    (so an auditor can too) and refuses clients whose budget would be exceeded
  * per-round Merkle root of commitments to client updates
  * commit-reveal randomness for audit selection (no manipulable blockhash)
  * reputation: failed audits lower a score; low score => excluded
  * survivor-set check: server may not silently drop a client that submitted
  * model-hash registry (tamper-evident model history)
"""
import hashlib, json, math

from . import merkle
from .accountant import RDPAccountant

REP_START, REP_FAIL, REP_PASS, REP_BAN = 1.0, 0.7, 0.05, 0.4   # one failed opening => ban (non-repudiable evidence)


def _hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


class Ledger:
    def __init__(self):
        self.blocks = []
        self.pending = []
        self.gas_total = 0
        self.gas_by_method = {}

    def tx(self, method, args, storage_bytes=0):
        calldata = len(json.dumps(args, default=str).encode())
        gas = 21000 + 16 * calldata + 20000 * math.ceil(storage_bytes / 32)
        self.pending.append({"method": method, "args": args, "gas": gas})
        self.gas_total += gas
        self.gas_by_method[method] = self.gas_by_method.get(method, 0) + gas
        return gas

    def seal(self, label=""):
        prev = self.blocks[-1]["hash"] if self.blocks else "0" * 64
        body = {"index": len(self.blocks), "prev": prev, "label": label, "txs": self.pending}
        body["hash"] = _hash({k: body[k] for k in ("index", "prev", "label", "txs")})
        self.blocks.append(body)
        self.pending = []
        return body["hash"]

    def head(self):
        return self.blocks[-1]["hash"] if self.blocks else "0" * 64

    def verify_chain(self):
        prev = "0" * 64
        for b in self.blocks:
            h = _hash({k: b[k] for k in ("index", "prev", "label", "txs")})
            if b["prev"] != prev or b["hash"] != h:
                return False, b["index"]
            prev = b["hash"]
        return True, None

    def to_json(self):
        return {"blocks": self.blocks, "gas_total": self.gas_total, "gas_by_method": self.gas_by_method}


class PrivacyContract(Ledger):
    def __init__(self, delta=1e-5, honest_min=None):
        super().__init__()
        self.delta = delta
        self.clients = {}
        self.rounds = {}
        self.events = []
        self.models = {}          # round -> model hash

    # ------------------------------------------------------------ helpers
    def _event(self, r, kind, **kw):
        self.events.append({"round": r, "type": kind, **kw})
        self.tx("Event", {"round": r, "type": kind, **kw}, storage_bytes=32)

    def _ev(self, r, kind, **kw):
        self._event(r, kind, **kw)

    @staticmethod
    def noise_multiplier(sigma, clip, noise_model, k):
        """Effective multiplier seen by an adversary who holds the aggregate.
        local: the server sees each update, so only the client's own noise counts (k=1).
        distributed: the aggregate carries the noise of k (assumed-honest) clients."""
        if sigma <= 0:
            return 0.0
        kk = 1 if noise_model == "local" else max(1, k)
        return sigma * math.sqrt(kk) / clip

    # ------------------------------------------------------------ registry / admission
    def register(self, cid, eps_max):
        self.clients[cid] = {"eps_max": eps_max, "rep": REP_START, "banned": False,
                             "acct": RDPAccountant(self.delta), "rounds": 0}
        self.tx("register", {"cid": cid, "eps_max": eps_max}, storage_bytes=96)

    def epsilon(self, cid):
        return self.clients[cid]["acct"].eps()

    def begin_round(self, r, candidates, plan, honest_k):
        """plan[cid] = (sigma, clip, noise_model). Returns (admitted, refused{cid: reason})."""
        self.rounds[r] = {"commit": {}, "nonces": {}, "nonce_hash": {}, "submitted": set(), "audits": {}}
        admitted, refused = [], {}
        for cid in candidates:
            c = self.clients[cid]
            sigma, clip, nm = plan[cid]
            if c["banned"]:
                refused[cid] = "banned (reputation)"
                continue
            z = self.noise_multiplier(sigma, clip, nm, honest_k)
            if z > 0:
                over = c["acct"].projected(z) > c["eps_max"]
            else:                                  # no noise declared: only allowed for an unbounded budget
                over = not math.isinf(c["eps_max"])
            if over:
                refused[cid] = "privacy budget exhausted" if z > 0 else "no noise declared"
                continue
            admitted.append(cid)
        for cid, why in refused.items():
            self._event(r, "refused", cid=cid, reason=why)
        self.tx("begin_round", {"round": r, "admitted": admitted}, storage_bytes=32 * len(admitted))
        return admitted, refused

    # ------------------------------------------------------------ commitments & randomness
    def post_intent(self, r, cid, sigma, clip, noise_model, seed_hash, nonce_hash):
        """Phase A: declare noise level, commit to the noise seed and to a beacon contribution."""
        self.rounds[r]["commit"][cid] = {"c": None, "sigma": sigma, "clip": clip, "nm": noise_model,
                                         "seed_hash": seed_hash}
        self.rounds[r]["nonce_hash"][cid] = nonce_hash
        self.tx("post_intent", {"round": r, "cid": cid, "sigma": sigma, "seed_hash": seed_hash[:16] + ".."},
                storage_bytes=32 * 3)

    def beacon(self, r):
        """Public randomness = H(all revealed nonces || chain head). Noise seeds are fixed *before* this exists."""
        rd = self.rounds[r]
        rd["beacon"] = hashlib.sha256(b"".join(rd["nonces"][c] for c in sorted(rd["nonces"])) + self.head().encode()).digest()
        return rd["beacon"]

    def post_commitment(self, r, cid, commit_hex):
        """Phase C: commitment to the final (noised, clipped) update."""
        self.rounds[r]["commit"][cid]["c"] = commit_hex
        self.tx("post_commitment", {"round": r, "cid": cid, "c": commit_hex[:16] + ".."}, storage_bytes=32 * 3)

    def post_proof(self, r, cid, proof_hash):
        self.rounds[r].setdefault("proofs", {})[cid] = proof_hash
        self.tx("post_proof", {"round": r, "cid": cid, "proof": proof_hash[:16] + ".."}, storage_bytes=32)

    def close_commitments(self, r):
        rd = self.rounds[r]
        leaves = [merkle.leaf(f"{cid}|{v['c']}|{v['sigma']}|{v['seed_hash']}".encode())
                  for cid, v in sorted(rd["commit"].items())]
        rd["order"] = sorted(rd["commit"])
        rd["leaves"] = leaves
        rd["root"] = merkle.root(leaves).hex()
        self.tx("close_commitments", {"round": r, "root": rd["root"]}, storage_bytes=32)
        return rd["root"]

    def inclusion_proof(self, r, cid):
        rd = self.rounds[r]
        i = rd["order"].index(cid)
        return rd["leaves"][i], merkle.proof(rd["leaves"], i), bytes.fromhex(rd["root"])

    def reveal_nonce(self, r, cid, nonce: bytes):
        rd = self.rounds[r]
        if hashlib.sha256(nonce).hexdigest() != rd["nonce_hash"].get(cid):
            self._event(r, "bad_nonce", cid=cid)
            return False
        rd["nonces"][cid] = nonce
        self.tx("reveal_nonce", {"round": r, "cid": cid}, storage_bytes=32)
        return True

    def select_audits(self, r, rate, min_one=True):
        """Audit seed = H(beacon || Merkle root of commitments): fixed only after every commitment is posted."""
        rd = self.rounds[r]
        seed = hashlib.sha256(rd["beacon"] + bytes.fromhex(rd["root"])).digest()
        chosen = []
        for cid in sorted(rd["commit"]):
            u = int.from_bytes(hashlib.sha256(seed + cid.to_bytes(4, "big")).digest(), "big") / 2 ** 256
            if u < rate:
                chosen.append(cid)
        rd["audit_set"] = chosen
        self.tx("select_audits", {"round": r, "set": chosen}, storage_bytes=32)
        return chosen

    def report_audit(self, r, cid, ok, reason=""):
        c = self.clients[cid]
        if ok:
            c["rep"] = min(REP_START, c["rep"] + REP_PASS)
        else:
            c["rep"] -= REP_FAIL
            if c["rep"] < REP_BAN:
                c["banned"] = True
            self._event(r, "audit_fail", cid=cid, reason=reason, rep=round(c["rep"], 2), banned=c["banned"])
        self.rounds[r]["audits"][cid] = (ok, reason)
        self.tx("report_audit", {"round": r, "cid": cid, "ok": ok}, storage_bytes=32)

    # ------------------------------------------------------------ aggregation record
    def submitted(self, r, cid, masked_hash=""):
        self.rounds[r]["submitted"].add(cid)
        self.rounds[r].setdefault("masked_hash", {})[cid] = masked_hash
        self.tx("submitted", {"round": r, "cid": cid}, storage_bytes=64)

    def post_aggregate(self, r, survivors, model_hash, agg_hash, verified, emergency=False, gate_ok=True):
        """Returns accepted(bool). Charges privacy budget for every survivor of an accepted or
        rejected-after-release round (the noisy aggregate was computed either way)."""
        rd = self.rounds[r]
        ok = True
        if set(survivors) != rd["submitted"]:
            self._event(r, "survivor_mismatch", declared=sorted(survivors), submitted=sorted(rd["submitted"]))
            ok = False
        if not verified:
            self._event(r, "aggregate_verification_failed")
            ok = False
        if not gate_ok:
            self._event(r, "gate_rejected")
            ok = False
        n_r = len(rd["submitted"])
        for cid in rd["submitted"]:
            v = rd["commit"][cid]
            z = self.noise_multiplier(v["sigma"], v["clip"], v["nm"], min(n_r, self._k))
            self.clients[cid]["acct"].add(z)
            self.clients[cid]["rounds"] += 1
        rd["accepted"] = ok
        rd["model_hash"] = model_hash if ok else None
        if ok:
            self.models[r] = model_hash
        self.tx("post_aggregate", {"round": r, "n": n_r, "model": (model_hash or "")[:16], "agg": agg_hash[:16],
                                   "ok": ok, "emergency": emergency}, storage_bytes=32 * 3)
        return ok

    _k = 10 ** 9  # honest-client assumption used for accounting; set by the federation

    def set_honest_k(self, k):
        self._k = max(1, k)
