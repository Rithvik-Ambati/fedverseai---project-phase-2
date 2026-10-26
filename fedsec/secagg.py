"""Secure aggregation with pairwise masking, self-masks and dropout recovery
(Bonawitz et al., CCS 2017, honest-but-curious server variant).

Vectors live in Z_q (q = the Pedersen group order) so masks cancel *exactly* and the
aggregate stays compatible with the homomorphic commitments.

Protocol per round (all simulated in one process; byte counts are tracked):
  1. every client generates an X25519 key pair and a self-mask seed b_u
  2. every client Shamir-shares (private key, b_u) among the roster, threshold t
  3. client u sends  y_u = x_u + PRG(b_u) + sum_{v>u} PRG(s_uv) - sum_{v<u} PRG(s_uv)
  4. server announces survivors; each survivor reveals, per peer,
        - the b-share if the peer survived, or the key-share if the peer dropped
     (never both: an honest client refuses, so the server cannot unmask a live client)
  5. server removes self-masks of survivors and the dangling pair masks of dropped clients
"""
import hashlib, json, random
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

SHAMIR_P = 2 ** 521 - 1


# ---------------------------------------------------------------- Shamir over GF(2^521-1)
def shamir_split(secret, ids, t, rng):
    coeffs = [secret % SHAMIR_P] + [rng.randrange(SHAMIR_P) for _ in range(t - 1)]
    out = {}
    for x in ids:
        xx = x + 1  # ids start at 0; evaluation point must be non-zero
        y = 0
        for c in reversed(coeffs):
            y = (y * xx + c) % SHAMIR_P
        out[x] = y
    return out


def shamir_recover(shares):
    """shares: {id: y}. Lagrange interpolation at 0."""
    xs = {i: i + 1 for i in shares}
    total = 0
    for i, yi in shares.items():
        num, den = 1, 1
        for j in shares:
            if i != j:
                num = (num * (-xs[j])) % SHAMIR_P
                den = (den * (xs[i] - xs[j])) % SHAMIR_P
        total = (total + yi * num * pow(den, -1, SHAMIR_P)) % SHAMIR_P
    return total


# ---------------------------------------------------------------- PRG / helpers
def prg(seed: bytes, length: int, q: int):
    """Expand a seed into `length` pseudo-random elements of Z_q (320 bits -> negligible bias)."""
    raw = hashlib.shake_256(seed).digest(length * 40)
    return [int.from_bytes(raw[i * 40:(i + 1) * 40], "big") % q for i in range(length)]


def _pair_seed(shared: bytes, rnd: int, a: int, b: int):
    lo, hi = min(a, b), max(a, b)
    return hashlib.sha256(b"pair" + shared + rnd.to_bytes(4, "big") + lo.to_bytes(4, "big") + hi.to_bytes(4, "big")).digest()


def _self_seed(b: int):
    return hashlib.sha256(b"self" + b.to_bytes(32, "big")).digest()


def _pub_bytes(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _priv_bytes(priv):
    return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


# ---------------------------------------------------------------- client / server roles
class SAClient:
    def __init__(self, cid, rng: random.Random):
        self.cid = cid
        self.rng = rng
        self.priv = X25519PrivateKey.from_private_bytes(rng.randbytes(32))
        self.pub = _pub_bytes(self.priv)
        self.b = int.from_bytes(rng.randbytes(32), "big")
        self.key_shares = {}   # peer -> share of peer's private key
        self.b_shares = {}     # peer -> share of peer's self-mask seed

    def make_shares(self, roster, t):
        s = shamir_split(int.from_bytes(_priv_bytes(self.priv), "big"), roster, t, self.rng)
        b = shamir_split(self.b, roster, t, self.rng)
        return {v: (s[v], b[v]) for v in roster}

    def receive_share(self, peer, s_share, b_share):
        self.key_shares[peer] = s_share
        self.b_shares[peer] = b_share

    def masked_input(self, vec, pubs, rnd, q):
        L = len(vec)
        y = [(v + m) % q for v, m in zip(vec, prg(_self_seed(self.b), L, q))]
        for v, pub in pubs.items():
            if v == self.cid:
                continue
            shared = self.priv.exchange(X25519PublicKey.from_public_bytes(pub))
            m = prg(_pair_seed(shared, rnd, self.cid, v), L, q)
            if self.cid < v:
                y = [(a + b) % q for a, b in zip(y, m)]
            else:
                y = [(a - b) % q for a, b in zip(y, m)]
        return y

    def mask_only(self, pubs, rnd, L, q):
        """The total additive mask this client applied (self mask + signed pair masks). Revealed to the auditor
        ONLY in the blame phase after a failed round."""
        m = prg(_self_seed(self.b), L, q)
        for v, pub in pubs.items():
            if v == self.cid:
                continue
            shared = self.priv.exchange(X25519PublicKey.from_public_bytes(pub))
            pm = prg(_pair_seed(shared, rnd, self.cid, v), L, q)
            m = [(a + b) % q for a, b in zip(m, pm)] if self.cid < v else [(a - b) % q for a, b in zip(m, pm)]
        return m

    def reveal(self, dropped, survivors):
        if set(dropped) & set(survivors):
            raise ValueError("refusing: peer listed as both dropped and surviving")
        return ({v: self.key_shares[v] for v in dropped if v in self.key_shares},
                {v: self.b_shares[v] for v in survivors if v in self.b_shares})


@dataclass
class SAResult:
    aggregate: list                      # sum of survivors' plaintext vectors, mod q
    survivors: list
    dropped: list
    masked: dict                         # what the server actually saw per client
    bytes_up: int = 0
    aborted: bool = False
    clients: dict = None                 # per-client state, used only by the simulated blame phase
    pubs: dict = None
    rnd: int = 0


def server_unmask(masked, survivors, dropped, pubs, key_pool, b_pool, rnd, q):
    """The (untrusted) server's final step: sum the masked vectors, strip survivors' self masks (rebuilt from >= t
    shares of b_v) and the dangling pair masks of dropped clients (rebuilt from >= t shares of their private key)."""
    L = len(masked[survivors[0]])
    agg = [0] * L
    for u in survivors:
        agg = [(a + y) % q for a, y in zip(agg, masked[u])]
    for v in survivors:                       # strip self masks
        bv = shamir_recover(b_pool[v])
        agg = [(a - m) % q for a, m in zip(agg, prg(_self_seed(bv), L, q))]
    for v in dropped:                         # strip dangling pair masks of dropped clients
        priv = X25519PrivateKey.from_private_bytes(shamir_recover(key_pool[v]).to_bytes(32, "big"))
        for u in survivors:
            shared = priv.exchange(X25519PublicKey.from_public_bytes(pubs[u]))
            m = prg(_pair_seed(shared, rnd, v, u), L, q)
            # u added +m if u < v else -m ; remove it
            agg = [(a - mm) % q for a, mm in zip(agg, m)] if u < v else [(a + mm) % q for a, mm in zip(agg, m)]
    return agg


# ---- authenticated-encryption of shares between two clients (the server only relays ciphertexts)
def _share_key(priv, peer_pub, a, b, rnd):
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    info = b"share|" + rnd.to_bytes(4, "big") + min(a, b).to_bytes(4, "big") + max(a, b).to_bytes(4, "big")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def seal_share(client, peer, peer_pub, s_share, b_share, rnd):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os
    key = _share_key(client.priv, peer_pub, client.cid, peer, rnd)
    nonce = os.urandom(12)
    aad = f"{client.cid}->{peer}|{rnd}".encode()
    ct = AESGCM(key).encrypt(nonce, json.dumps([hex(s_share), hex(b_share)]).encode(), aad)
    return {"nonce": nonce.hex(), "ct": ct.hex()}


def open_share(client, sender, sender_pub, blob, rnd):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _share_key(client.priv, sender_pub, client.cid, sender, rnd)
    aad = f"{sender}->{client.cid}|{rnd}".encode()
    s, b = json.loads(AESGCM(key).decrypt(bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["ct"]), aad))
    return int(s, 16), int(b, 16)


def secure_aggregate(vectors, roster, dropped_after_share, rnd, q, t=None, seed=0):
    """Run one SecAgg round.

    vectors: {cid: list[int] in Z_q} for clients that would contribute
    roster: ordered list of participating client ids
    dropped_after_share: set of cids that vanish after key sharing (before sending input)
    """
    rng = random.Random(f"secagg-{seed}-{rnd}")
    n = len(roster)
    t = t or (n // 2 + 1)
    clients = {u: SAClient(u, random.Random(rng.random())) for u in roster}
    pubs = {u: c.pub for u, c in clients.items()}
    bytes_up = 0
    for u in roster:  # share keys
        for v, (s, b) in clients[u].make_shares(roster, t).items():
            clients[v].receive_share(u, s, b)
            bytes_up += 2 * 66
    survivors = [u for u in roster if u not in dropped_after_share]
    dropped = [u for u in roster if u in dropped_after_share]
    if len(survivors) < t:
        return SAResult([], survivors, dropped, {}, bytes_up, aborted=True)
    L = len(next(iter(vectors.values())))
    masked = {}
    for u in survivors:
        masked[u] = clients[u].masked_input(vectors[u], pubs, rnd, q)
        bytes_up += L * 32
    # --- server: collect reveals from the surviving clients
    key_pool = {v: {} for v in dropped}
    b_pool = {v: {} for v in survivors}
    for u in survivors:
        ks, bs = clients[u].reveal(dropped, survivors)
        for v, sh in ks.items():
            key_pool[v][u] = sh
        for v, sh in bs.items():
            b_pool[v][u] = sh
        bytes_up += (len(ks) + len(bs)) * 66
    agg = server_unmask(masked, survivors, dropped, pubs, key_pool, b_pool, rnd, q)
    return SAResult(agg, survivors, dropped, masked, bytes_up, clients=clients, pubs=pubs, rnd=rnd)
