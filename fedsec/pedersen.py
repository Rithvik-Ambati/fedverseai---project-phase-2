"""Vector Pedersen commitments in a Schnorr group: Com(x; r) = g^r * prod_i h_i^{x_i}.

Perfectly hiding, computationally binding, and additively homomorphic:
    Com(x1; r1) * Com(x2; r2) = Com(x1 + x2; r1 + r2)    (exponents mod q)
That homomorphism is what lets anyone check that a published aggregate equals the
sum of the updates that were committed on the ledger.
"""
import hashlib, json, os, secrets

_PATH = os.path.join(os.path.dirname(__file__), "group_params.json")


class Group:
    def __init__(self, p, q):
        self.p, self.q = p, q
        self._h = []
        self._hinv = []
        self.g = self._hash_to_group(b"fedsec-g")

    def _hash_to_group(self, label):
        out = b""
        c = 0
        while len(out) < (self.p.bit_length() + 7) // 8 + 16:
            out += hashlib.sha256(label + c.to_bytes(4, "big")).digest()
            c += 1
        return pow(int.from_bytes(out, "big") % self.p, (self.p - 1) // self.q, self.p)

    def h(self, i):
        while len(self._h) <= i:
            self._h.append(self._hash_to_group(b"fedsec-h" + len(self._h).to_bytes(4, "big")))
        return self._h[i]

    def _hinv_i(self, i):
        while len(self._hinv) <= i:
            self._hinv.append(pow(self.h(len(self._hinv)), -1, self.p))
        return self._hinv[i]

    def rand_scalar(self):
        return secrets.randbelow(self.q)

    def commit(self, vec, r):
        """vec: iterable of ints (any sign / size; reduced mod q). Returns group element (int)."""
        p, q = self.p, self.q
        acc = pow(self.g, r % q, p)
        half = q // 2
        for i, x in enumerate(vec):
            x %= q
            if x > half:        # small negative numbers: use the inverse generator with a tiny exponent
                acc = (acc * pow(self._hinv_i(i), q - x, p)) % p
            elif x:
                acc = (acc * pow(self.h(i), x, p)) % p
        return acc

    def combine(self, commitments):
        acc = 1
        for c in commitments:
            acc = (acc * c) % self.p
        return acc

    def open_ok(self, c, vec, r):
        return self.commit(vec, r) == c


_GROUP = None


def get_group():
    global _GROUP
    if _GROUP is None:
        with open(_PATH) as f:
            d = json.load(f)
        _GROUP = Group(int(d["p"], 16), int(d["q"], 16))
    return _GROUP
