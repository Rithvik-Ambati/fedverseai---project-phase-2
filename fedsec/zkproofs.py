"""Zero-knowledge proof that a committed update has bounded L2 norm  (no trusted auditor needed).

Statement.  The prover holds an integer vector c = (c_1..c_d) and publishes the Pedersen vector commitment
    Com_c = g^r * prod_i h_i^{c_i}
and proves  sum_i c_i^2 <= B  *without revealing c*. Anyone can verify, every round, for every client.

Construction (Sigma protocols + Fiat-Shamir, in the Schnorr group of `pedersen.py`; no trusted setup, no pairings)
  1. per-coordinate commitments  P_i = h_i^{c_i} g^{r_i}  (with sum r_i = r, so prod P_i = Com_c),
                                 A_i = u^{c_i} g^{s_i},   Q_i = u^{c_i^2} g^{t_i}
     and a Sigma proof of knowledge of (a, ra, s, tau) with the SAME a in
        P_i = h_i^a g^{ra},   A_i = u^a g^s,   Q_i = A_i^a g^{tau}      (tau = t_i - a s_i)
     => Q_i commits to the square of the value inside P_i.
  2. sum of squares:  prod Q_i = u^{sum c_i^2} g^{sum t_i}.  Slack  w = B - sum c_i^2  is committed by
        V = u^B / prod Q_i = u^w g^{-sum t_i}.
  3. range proof  0 <= w < 2^k  by bit decomposition: bit commitments D_j = u^{b_j} g^{rho_j} with
        prod D_j^{2^j} = V, and a Schnorr OR-proof that each D_j hides 0 or 1.
     Together: sum c_i^2 = B - w <= B.

Soundness rests on discrete-log hardness (Fiat-Shamir heuristic); zero-knowledge is perfect/statistical for the
Sigma parts. Cost is O(d + log B) group exponentiations - fine for small models, heavy for large ones (see
`experiments` for measured timings). The *noise* is outside this proof: noise correctness is still checked by the
seeded audit, which now only needs to reveal the noise seed (not the update).
"""
import hashlib
import secrets

from .pedersen import get_group


def _u(G):
    if not hasattr(G, "_u"):
        G._u = G._hash_to_group(b"fedsec-u")
    return G._u


def _H(G, *items):
    h = hashlib.sha256()
    for it in items:
        h.update(it if isinstance(it, bytes) else int(it).to_bytes((G.p.bit_length() + 7) // 8 + 1, "big"))
    return int.from_bytes(h.digest(), "big") % G.q


def _rand(G):
    return secrets.randbelow(G.q)


def _inv(G, x):
    return pow(x, -1, G.p)


def bound_for(clip_int, d):
    """Integer bound B on sum c_i^2 that tolerates fixed-point rounding of a vector with norm <= clip."""
    return (clip_int + int(d ** 0.5) + 1) ** 2


def prove(G, c, B, ctx, rng=None):
    """Return (proof dict, Com_c, r_total). `c`: list of ints. `ctx`: bytes binding the proof to round/client."""
    g, u, q, p = G.g, _u(G), G.q, G.p
    d = len(c)
    rand = rng.randrange if rng else (lambda n: secrets.randbelow(n))
    r = [rand(q) for _ in range(d)]
    s = [rand(q) for _ in range(d)]
    t = [rand(q) for _ in range(d)]
    P = [(pow(G.h(i), c[i] % q, p) * pow(g, r[i], p)) % p for i in range(d)]
    A = [(pow(u, c[i] % q, p) * pow(g, s[i], p)) % p for i in range(d)]
    Q = [(pow(u, (c[i] * c[i]) % q, p) * pow(g, t[i], p)) % p for i in range(d)]
    conj = []
    for i in range(d):
        a = c[i] % q
        tau = (t[i] - a * s[i]) % q
        al, r1, r2, r3 = rand(q), rand(q), rand(q), rand(q)
        T1 = (pow(G.h(i), al, p) * pow(g, r1, p)) % p
        T2 = (pow(u, al, p) * pow(g, r2, p)) % p
        T3 = (pow(A[i], al, p) * pow(g, r3, p)) % p
        e = _H(G, ctx, i, P[i], A[i], Q[i], T1, T2, T3)
        conj.append((e, (al + e * a) % q, (r1 + e * r[i]) % q, (r2 + e * s[i]) % q, (r3 + e * tau) % q))
    # slack and range proof
    w = B - sum(ci * ci for ci in c)
    k = B.bit_length() + 1
    rho = (-sum(t)) % q
    V = (pow(u, B % q, p) * _inv(G, _prod(Q, p))) % p
    bits = [(w >> j) & 1 for j in range(k)] if w >= 0 else [((w % (1 << k)) >> j) & 1 for j in range(k)]
    rj = [rand(q) for _ in range(k - 1)]
    last = ((rho - sum((pow(2, j, q) * rj[j]) % q for j in range(k - 1))) * pow(pow(2, k - 1, q), -1, q)) % q
    rj.append(last)
    D = [(pow(u, bits[j], p) * pow(g, rj[j], p)) % p for j in range(k)]
    orp = [_prove_bit(G, D[j], bits[j], rj[j], ctx, j, rand) for j in range(k)]
    Com_c = _prod(P, p)
    proof = {"P": P, "A": A, "Q": Q, "conj": conj, "D": D, "or": orp, "k": k}
    return proof, Com_c, sum(r) % q


def _prod(xs, p):
    acc = 1
    for x in xs:
        acc = (acc * x) % p
    return acc


def _prove_bit(G, Dj, b, rho, ctx, j, rand):
    g, u, q, p = G.g, _u(G), G.q, G.p
    D1 = (Dj * _inv(G, u)) % p                       # D / u
    if b == 0:
        al = rand(q)
        T0 = pow(g, al, p)
        e1, z1 = rand(q), rand(q)
        T1 = (pow(g, z1, p) * pow(_inv(G, D1), e1, p)) % p
        e = _H(G, ctx, b"bit", j, Dj, T0, T1)
        e0 = (e - e1) % q
        z0 = (al + e0 * rho) % q
    else:
        al = rand(q)
        T1 = pow(g, al, p)
        e0, z0 = rand(q), rand(q)
        T0 = (pow(g, z0, p) * pow(_inv(G, Dj), e0, p)) % p
        e = _H(G, ctx, b"bit", j, Dj, T0, T1)
        e1 = (e - e0) % q
        z1 = (al + e1 * rho) % q
    return (e0, z0, e1, z1)


def verify(G, proof, Com_c, B, ctx):
    g, u, q, p = G.g, _u(G), G.q, G.p
    try:
        P, A, Q, conj, D, orp, k = (proof[x] for x in ("P", "A", "Q", "conj", "D", "or", "k"))
        d = len(P)
        if not (len(A) == len(Q) == len(conj) == d) or len(D) != k or len(orp) != k or k != B.bit_length() + 1:
            return False
        if _prod(P, p) != Com_c % p:
            return False
        for i in range(d):
            e, zA, z1, z2, z3 = conj[i]
            T1 = (pow(G.h(i), zA, p) * pow(g, z1, p) * pow(_inv(G, P[i]), e, p)) % p
            T2 = (pow(u, zA, p) * pow(g, z2, p) * pow(_inv(G, A[i]), e, p)) % p
            T3 = (pow(A[i], zA, p) * pow(g, z3, p) * pow(_inv(G, Q[i]), e, p)) % p
            if _H(G, ctx, i, P[i], A[i], Q[i], T1, T2, T3) != e % q:
                return False
        V = (pow(u, B % q, p) * _inv(G, _prod(Q, p))) % p
        acc = 1
        for j in range(k):
            acc = (acc * pow(D[j], pow(2, j, q), p)) % p
        if acc != V:
            return False
        for j in range(k):
            e0, z0, e1, z1 = orp[j]
            D1 = (D[j] * _inv(G, u)) % p
            T0 = (pow(g, z0, p) * pow(_inv(G, D[j]), e0, p)) % p
            T1 = (pow(g, z1, p) * pow(_inv(G, D1), e1, p)) % p
            if (e0 + e1) % q != _H(G, ctx, b"bit", j, D[j], T0, T1):
                return False
        return True
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return False


def proof_size_bytes(proof, G):
    el = (G.p.bit_length() + 7) // 8
    sc = (G.q.bit_length() + 7) // 8
    d = len(proof["P"])
    return 3 * d * el + d * 5 * sc + proof["k"] * (el + 4 * sc)
