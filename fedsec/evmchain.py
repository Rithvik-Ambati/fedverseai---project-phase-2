"""Real-blockchain backend: the PrivacyLedger Solidity contract on a local Hardhat (EVM) chain, driven with web3.py.

Drop-in replacement for `ledger.PrivacyContract`: the federation calls the same methods, but every action is now
a *signed transaction from a separate account* (owner / server / auditor / one account per hospital) that is
mined into a real block, costs real (EVM-metered) gas, and is checked by the contract's own code.

Differences from the simulated ledger worth knowing
  * epsilon accounting runs on-chain in fixed point over a 32-point RDP grid (slightly coarser than the
    simulator's 170-point grid, so values agree to within a fraction of a percent, rounded up)
  * hashes on-chain are keccak256 / sha256 (EVM native); commitments to client updates are the same Pedersen
    commitments, logged in full as events, with their keccak hash in contract storage
  * the Pedersen homomorphic check of the aggregate is performed off-chain (anyone can redo it from the
    logged commitments); the server posts the verdict
  * a single local Hardhat node is NOT decentralised; run several nodes (Besu / Geth) for real consensus
"""
import atexit, contextlib, json, math, os, shutil, subprocess, sys, time

from eth_utils import keccak
from web3 import Web3

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chain")
ARTIFACT = os.path.join(ROOT, "artifacts", "contracts", "PrivacyLedger.sol", "PrivacyLedger.json")
RPC = os.environ.get("FEDSEC_RPC", "http://127.0.0.1:8545")
S = 10 ** 18
Q = 10 ** 9   # fixed point for sigma / clip

ALPHAS = [1.1, 1.2, 1.3, 1.5, 1.75, 2, 2.5, 3, 3.5, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64,
          80, 96, 128, 192, 256, 512]
REASONS = {1: "banned (reputation)", 2: "privacy budget exhausted", 3: "no noise declared", 4: "not registered",
           5: "insufficient stake"}
UNLIMITED = 2 ** 256 - 1
GAS_LIMIT = 8_000_000      # far above any single call here (largest ~1.3M gas), below the EVM per-tx cap

_node = {"proc": None, "w3": None}


def _stop_node():
    p = _node["proc"]
    if p and p.poll() is None:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
        else:
            p.terminate()


def get_w3(start=True, timeout=90):
    """Connect to the local chain, starting `hardhat node` ourselves if nothing is listening."""
    if _node["w3"] is not None:
        return _node["w3"]
    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 60}))
    if not w3.is_connected():
        if not start:
            raise ConnectionError(f"no chain at {RPC}; run `npx hardhat node` in {ROOT}")
        npx = shutil.which("npx") or "npx"
        log = open(os.path.join(ROOT, "node.log"), "w")
        port = RPC.rsplit(":", 1)[-1].strip("/")
        _node["proc"] = subprocess.Popen([npx, "hardhat", "node", "--port", port], cwd=ROOT, stdout=log, stderr=log)
        atexit.register(_stop_node)
        t0 = time.time()
        while not w3.is_connected():
            if time.time() - t0 > timeout:
                raise TimeoutError("hardhat node did not start (see chain/node.log)")
            time.sleep(0.5)
    _node["w3"] = w3
    return w3


def load_artifact():
    if not os.path.exists(ARTIFACT):
        subprocess.run([shutil.which("npx") or "npx", "hardhat", "compile"], cwd=ROOT, check=True)
    with open(ARTIFACT) as f:
        return json.load(f)


def _topic_map(contract):
    out = {}
    for item in contract.abi:
        if item.get("type") == "event":
            sig = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
            out["0x" + keccak(text=sig).hex().removeprefix("0x")] = item["name"]
    return out


class _Models:
    def __init__(self, chain):
        self.chain = chain

    def get(self, r, default=None):
        h = self.chain.contract.functions.models(r).call()
        return h.hex() if int.from_bytes(h, "big") else default


class EVMChain:
    """Same surface as `PrivacyContract`, backed by a real EVM chain."""

    backend = "evm"

    def __init__(self, delta=1e-5, audit_rate=0.25, n_clients=8, start_node=True, min_stake=0.0, slash=0.0,
                 rpc=None, local_signing=False):
        self.local_signing = local_signing
        if local_signing:        # e.g. Besu: the node holds no accounts, so every role signs its own transactions
            from web3.middleware import SignAndSendRawMiddlewareBuilder
            from .besunet import dev_accounts
            self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
            keys = dev_accounts(n_clients + 3)
            from web3.middleware import ExtraDataToPOAMiddleware       # QBFT blocks carry validator seals in extraData
            self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            self.w3.middleware_onion.inject(SignAndSendRawMiddlewareBuilder.build(keys), layer=0)
            self._accounts = [k.address for k in keys]
        else:
            self.w3 = get_w3(start_node)
            self._accounts = list(self.w3.eth.accounts)
        self._poll = 0.1 if local_signing else 0.005
        self._batch = None
        art = load_artifact()
        acc = self._accounts
        assert len(acc) >= n_clients + 3, "node needs more funded accounts"
        self.owner, self.server, self.auditor = acc[0], acc[1], acc[2]
        self.client_addr = {i: acc[3 + i] for i in range(n_clients)}
        self.cid_of = {a: i for i, a in self.client_addr.items()}
        conv = [int(round((math.log1p(-1 / a) - (math.log(delta) + math.log(a)) / (a - 1)) * S)) for a in ALPHAS]
        alphas = [int(round(a * S)) for a in ALPHAS]
        factory = self.w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
        h = factory.constructor(self.server, self.auditor, alphas, conv, int(audit_rate * 1_000_000),
                                        int(min_stake * S), int(slash * S)).transact(
            {"from": self.owner, "gas": 8_000_000})
        rcpt = self.w3.eth.wait_for_transaction_receipt(h, poll_latency=self._poll)
        self.address = rcpt["contractAddress"]
        self.contract = self.w3.eth.contract(address=self.address, abi=art["abi"])
        self.topics = _topic_map(self.contract)
        self.delta = delta
        self._k = 10 ** 9
        self.events, self.clients, self.rounds = [], {}, {}
        self.tx_log, self._pending, self.groups = [], [], []
        self.gas_total, self.gas_by_method = rcpt["gasUsed"], {"deploy": rcpt["gasUsed"]}
        self.block_hash = {}
        self.audit_ppm = int(audit_rate * 1_000_000)
        self.models = _Models(self)

    # ------------------------------------------------------------------ plumbing
    def set_honest_k(self, k):
        self._k = max(1, k)

    @contextlib.contextmanager
    def batch(self):
        """Submit several transactions (each from a different account) without waiting, then collect all receipts:
        on a chain with 1 s blocks they land in one block instead of costing one block each."""
        self._batch = []
        try:
            yield
        finally:
            pending, self._batch = self._batch, None
        for h, fn_name, display in pending:
            self._finalize(h, fn_name, display)

    def _send(self, fn_name, sender, *args, display=None):
        fn = getattr(self.contract.functions, fn_name)(*args)
        h = fn.transact({"from": sender, "gas": GAS_LIMIT})      # fixed limit: skips one estimateGas round-trip
        if self._batch is not None:
            self._batch.append((h, fn_name, display))
            return []
        return self._finalize(h, fn_name, display)

    def _finalize(self, h, fn_name, display):
        rcpt = self.w3.eth.wait_for_transaction_receipt(h, poll_latency=self._poll)
        if rcpt["status"] != 1:
            raise RuntimeError(f"transaction {fn_name} reverted")
        self.block_hash[rcpt["blockNumber"]] = rcpt["blockHash"].hex()
        gas = rcpt["gasUsed"]
        self.gas_total += gas
        self.gas_by_method[fn_name] = self.gas_by_method.get(fn_name, 0) + gas
        rec = {"method": fn_name, "gas": gas, "block": rcpt["blockNumber"], "tx": h.hex(),
               "args": display if display is not None else {}}
        self.tx_log.append(rec)
        self._pending.append(rec)
        return self._decode_logs(rcpt)

    def _decode_logs(self, rcpt):
        out = []
        for log in rcpt["logs"]:
            name = self.topics.get("0x" + log["topics"][0].hex().removeprefix("0x"))
            if name:
                out.append((name, getattr(self.contract.events, name)().process_log(log)["args"]))
        return out

    def _ev(self, r, kind, **kw):
        self.events.append({"round": r, "type": kind, **kw})

    def _addr(self, cid):
        return self.client_addr[cid]

    # ------------------------------------------------------------------ registry / admission
    def register(self, cid, eps_max):
        self.clients[cid] = {"eps_max": eps_max, "banned": False, "rep": 1.0}
        v = UNLIMITED if math.isinf(eps_max) else int(eps_max * S)
        self._send("register", self.owner, self._addr(cid), v, display={"cid": cid, "eps_max": eps_max})

    def deposit(self, cid, eth):
        self.w3.eth.wait_for_transaction_receipt(
            self.contract.functions.deposit().transact({"from": self._addr(cid), "value": int(eth * S), "gas": GAS_LIMIT}))
        self.tx_log.append({"method": "deposit", "gas": 0, "block": self.w3.eth.block_number, "tx": "", "args": {"cid": cid, "eth": eth}})

    def post_server_bond(self, eth):
        self.w3.eth.wait_for_transaction_receipt(
            self.contract.functions.postServerBond().transact({"from": self.server, "value": int(eth * S), "gas": GAS_LIMIT}))

    def slash_server(self, r):
        self._send("slashServer", self.auditor, r, display={"round": r})

    def distribute_rewards(self):
        self._send("distributeRewards", self.owner, display={})

    def withdraw(self, cid):
        self._send("withdraw", self._addr(cid), display={"cid": cid})

    def balances(self):
        f = self.contract.functions
        out = {cid: {"stake": f.stake(a).call() / S, "credit": f.credit(a).call() / S} for cid, a in self.client_addr.items()}
        out["server_bond"] = f.serverBond().call() / S
        out["pool"] = f.rewardPool().call() / S
        return out

    def epsilon(self, cid):
        return self.contract.functions.epsilon(self._addr(cid)).call() / S

    def begin_round(self, r, candidates, plan, honest_k):
        nm = 0 if plan[candidates[0]][2] == "local" else 1
        clip = int(round(plan[candidates[0]][1] * Q))
        sig = [int(round(plan[c][0] * Q)) for c in candidates]
        evs = self._send("beginRound", self.server, r, [self._addr(c) for c in candidates], sig, clip, nm, honest_k,
                         display={"round": r, "candidates": list(candidates)})
        admitted = [self.cid_of[a] for a in self.contract.functions.getAdmitted(r).call()]
        refused = {}
        for name, a in evs:
            if name == "Refused":
                cid = self.cid_of[a["client"]]
                refused[cid] = REASONS[a["reason"]]
                self._ev(r, "refused", cid=cid, reason=refused[cid])
        self.rounds[r] = {"commit": {c: {"c": None, "sigma": plan[c][0], "clip": plan[c][1], "nm": plan[c][2],
                                         "seed_hash": None} for c in admitted}, "admitted": admitted}
        self.tx_log[-1]["args"]["admitted"] = admitted
        return admitted, refused

    # ------------------------------------------------------------------ commit / reveal / audit
    def post_intent(self, r, cid, sigma, clip, noise_model, seed_hash, nonce_hash):
        self._send("postIntent", self._addr(cid), r, int(round(sigma * Q)), bytes.fromhex(seed_hash),
                   bytes.fromhex(nonce_hash), display={"round": r, "cid": cid, "sigma": sigma,
                                                       "seed_hash": seed_hash[:16] + ".."})
        self.rounds[r]["commit"][cid]["seed_hash"] = seed_hash

    def reveal_nonce(self, r, cid, nonce):
        evs = self._send("revealNonce", self._addr(cid), r, nonce, display={"round": r, "cid": cid})
        if any(n == "BadNonce" for n, _ in evs):
            self._ev(r, "bad_nonce", cid=cid)
            return False
        return True

    def beacon(self, r):
        self._send("closeReveals", self.server, r, display={"round": r})
        b = self.contract.functions.getBeacon(r).call()
        self.rounds[r]["beacon"] = b
        return b

    @staticmethod
    def _c128(commit_hex):
        """Canonical 128-byte big-endian encoding of a 1024-bit group element."""
        return int(commit_hex, 16).to_bytes(128, "big")

    def post_commitment(self, r, cid, commit_hex):
        h = self._c128(commit_hex).hex()
        self._send("postCommitment", self._addr(cid), r, bytes.fromhex(h),
                   display={"round": r, "cid": cid, "c": "0x" + h[:14] + ".."})
        self.rounds[r]["commit"][cid]["c"] = commit_hex

    def post_proof(self, r, cid, proof_hash):
        self._send("postProof", self._addr(cid), r, bytes.fromhex(proof_hash),
                   display={"round": r, "cid": cid, "proof": proof_hash[:16] + ".."})

    def verify_aggregate_onchain(self, r, survivors, X, R, G):
        """The contract checks prod C_u == Com(X; R) itself (modexp precompile). Returns its verdict."""
        if not getattr(self, "_group_set", False):
            self._send("setGroup", self.owner, G.p.to_bytes(128, "big"), G.g.to_bytes(128, "big"),
                       [G.h(i).to_bytes(128, "big") for i in range(len(X))], display={"generators": len(X)})
            self._group_set = True
        commits = [self._c128(self.rounds[r]["commit"][u]["c"]) for u in survivors]
        evs = self._send("verifyAggregate", self.server, r, [self._addr(u) for u in survivors], commits,
                         [int(x) % G.q for x in X], int(R) % G.q,
                         display={"round": r, "survivors": list(survivors), "terms": len(X)})
        return any(n == "AggregateChecked" and a["ok"] for n, a in evs)

    def close_commitments(self, r):
        self._send("closeCommitments", self.server, r, display={"round": r})
        root = self.contract.functions.getRoot(r).call()
        self.rounds[r]["root"] = root.hex()
        return root.hex()

    def _leaf(self, r, cid):
        rec = self.rounds[r]["commit"][cid]
        commit_hash = keccak(self._c128(rec["c"]))
        return keccak(bytes.fromhex(self._addr(cid)[2:]) + commit_hash + int(round(rec["sigma"] * Q)).to_bytes(32, "big")
                      + bytes.fromhex(rec["seed_hash"]))

    def inclusion_proof(self, r, cid):
        """Merkle proof (keccak, same construction as the contract) that `cid`'s commitment is in the round root."""
        order = [c for c in self.rounds[r]["admitted"] if self.rounds[r]["commit"][c]["c"]]
        level = [self._leaf(r, c) for c in order]
        idx = order.index(cid)
        leaf, path = level[idx], []
        while len(level) > 1:
            sib = idx ^ 1
            path.append((level[sib] if sib < len(level) else level[idx], True if sib > idx or sib >= len(level) else False))
            level = [keccak(level[i] + (level[i + 1] if i + 1 < len(level) else level[i])) for i in range(0, len(level), 2)]
            idx //= 2
        return leaf, path, bytes.fromhex(self.rounds[r]["root"])

    @staticmethod
    def verify_inclusion(leaf, path, root):
        cur = leaf
        for sib, sib_right in path:
            cur = keccak(cur + sib) if sib_right else keccak(sib + cur)
        return cur == root

    def select_audits(self, r, rate):
        ppm = int(rate * 1_000_000)
        if ppm != self.audit_ppm:
            self._send("setAuditRate", self.owner, ppm, display={"ppm": ppm})
            self.audit_ppm = ppm
        self._send("selectAudits", self.server, r, display={"round": r})
        chosen = [self.cid_of[a] for a in self.contract.functions.getAuditSet(r).call()]
        self.rounds[r]["audit_set"] = chosen
        self.tx_log[-1]["args"]["set"] = chosen
        return chosen

    def report_audit(self, r, cid, ok, reason=""):
        evs = self._send("reportAudit", self.auditor, r, self._addr(cid), bool(ok), reason or "",
                         display={"round": r, "cid": cid, "ok": bool(ok)})
        for name, a in evs:
            if name == "AuditResult":
                self.clients[cid]["rep"] = a["rep"] / 10000
                self.clients[cid]["banned"] = a["banned"]
                if not ok:
                    self._ev(r, "audit_fail", cid=cid, reason=reason, rep=round(a["rep"] / 10000, 2), banned=a["banned"])

    # ------------------------------------------------------------------ aggregation record
    def submitted(self, r, cid, masked_hash=""):
        h = bytes.fromhex(masked_hash) if masked_hash else b"\0" * 32
        self._send("markSubmitted", self._addr(cid), r, h, display={"round": r, "cid": cid})
        self.rounds[r].setdefault("masked_hash", {})[cid] = masked_hash

    def post_aggregate(self, r, survivors, model_hash, agg_hash, verified, emergency=False, gate_ok=True):
        flags = (1 if verified else 0) | (2 if emergency else 0) | (4 if gate_ok else 0)
        evs = self._send("postAggregate", self.server, r, [self._addr(c) for c in survivors],
                         bytes.fromhex(model_hash), bytes.fromhex(agg_hash), flags,
                         display={"round": r, "survivors": list(survivors), "model": model_hash[:16],
                                  "ok": None, "emergency": bool(emergency)})
        ok = False
        for name, a in evs:
            if name == "SurvivorMismatch":
                self._ev(r, "survivor_mismatch", declared=sorted(survivors))
            elif name == "VerificationFailed":
                self._ev(r, "aggregate_verification_failed")
            elif name == "GateRejected":
                self._ev(r, "gate_rejected")
            elif name == "Aggregated":
                ok = a["accepted"]
        self.tx_log[-1]["args"]["ok"] = ok
        return ok

    # ------------------------------------------------------------------ blocks / verification (for the UI)
    def seal(self, label=""):
        if not self._pending:
            return
        for rec in self._pending:
            rec["digest"] = self._digest(rec)
        first, last = self._pending[0]["block"], self._pending[-1]["block"]
        prev = self.w3.eth.get_block(first - 1)["hash"].hex() if first > 0 else "0" * 64
        self.groups.append({"index": len(self.groups), "label": label, "txs": list(self._pending),
                            "first_block": first, "last_block": last, "prev": prev,
                            "hash": self.block_hash[last]})
        self._pending = []

    @property
    def blocks(self):
        return self.groups

    def verify_chain(self):
        """(1) node's blocks are hash-linked; (2) block hashes still equal what we recorded when each tx was mined;
        (3) every recorded transaction still matches what the chain holds (method, gas, arguments' digest)."""
        prev = None
        for n in range(0, self.w3.eth.block_number + 1):
            b = self.w3.eth.get_block(n)
            if prev is not None and b["parentHash"].hex() != prev:
                return False, self._group_of_block(n)
            if n in self.block_hash and self.block_hash[n] != b["hash"].hex():
                return False, self._group_of_block(n)
            prev = b["hash"].hex()
        for g in self.groups:
            for rec in g["txs"]:
                tx = self.w3.eth.get_transaction(rec["tx"])
                fn, _ = self.contract.decode_function_input(tx["input"])
                rc = self.w3.eth.get_transaction_receipt(rec["tx"])
                if fn.fn_name != rec["method"] or rc["gasUsed"] != rec["gas"] or rec["block"] != rc["blockNumber"]:
                    return False, g["index"]
                if self._digest(rec) != rec.get("digest"):
                    return False, g["index"]
        return True, None

    @staticmethod
    def _digest(rec):
        return keccak(json.dumps(rec["args"], sort_keys=True, default=str).encode()).hex()

    def _group_of_block(self, n):
        for g in self.groups:
            if g["first_block"] <= n <= g["last_block"]:
                return g["index"]
        return None

    def head(self):
        return self.w3.eth.get_block("latest")["hash"].hex()
