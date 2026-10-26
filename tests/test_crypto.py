import random

import pytest

from fedsec import merkle
from fedsec.accountant import RDPAccountant, eps_for, noise_for_eps
from fedsec.gen_group import is_prime
from fedsec.pedersen import get_group
from fedsec.secagg import secure_aggregate, shamir_recover, shamir_split

G = get_group()


def test_group_valid():
    assert is_prime(G.p) and is_prime(G.q) and (G.p - 1) % G.q == 0
    assert pow(G.g, G.q, G.p) == 1 and pow(G.h(7), G.q, G.p) == 1


def test_pedersen_homomorphic_and_binding():
    r1, r2 = G.rand_scalar(), G.rand_scalar()
    a, b = [3, -5, 7], [10, 2, -9]
    c1, c2 = G.commit(a, r1), G.commit(b, r2)
    s = [x + y for x, y in zip(a, b)]
    assert G.combine([c1, c2]) == G.commit(s, r1 + r2)
    assert G.open_ok(c1, a, r1)
    assert not G.open_ok(c1, [3, -5, 8], r1)


def test_shamir():
    rng = random.Random(0)
    sh = shamir_split(987654321987654321, list(range(7)), 4, rng)
    assert shamir_recover({k: sh[k] for k in (1, 3, 4, 6)}) == 987654321987654321
    assert shamir_recover({k: sh[k] for k in (0, 1, 2)}) != 987654321987654321


@pytest.mark.parametrize("drop", [set(), {1, 5}, {0, 7, 3}])
def test_secagg_exact_with_dropouts(drop):
    rng = random.Random(1)
    q = G.q
    vec = {u: [rng.randrange(q) for _ in range(30)] for u in range(8)}
    res = secure_aggregate(vec, list(range(8)), drop, 3, q)
    exp = [sum(vec[u][i] for u in range(8) if u not in drop) % q for i in range(30)]
    assert not res.aborted and res.aggregate == exp
    # the server's view of a single client is unrelated to the plaintext
    assert all(res.masked[u] != vec[u] for u in res.masked)


def test_secagg_aborts_below_threshold():
    q = G.q
    vec = {u: [1, 2] for u in range(6)}
    assert secure_aggregate(vec, list(range(6)), {0, 1, 2, 3}, 0, q).aborted


def test_merkle():
    leaves = [merkle.leaf(bytes([i])) for i in range(7)]
    root = merkle.root(leaves)
    for i in range(7):
        assert merkle.verify(leaves[i], merkle.proof(leaves, i), root)
    assert not merkle.verify(merkle.leaf(b"x"), merkle.proof(leaves, 2), root)


def test_accountant_monotone_and_inverse():
    assert eps_for(2.0, 10) > eps_for(2.0, 5) > 0
    assert eps_for(1.0, 10) > eps_for(3.0, 10)
    z = noise_for_eps(8.0, 30)
    assert abs(eps_for(z, 30) - 8.0) < 0.05
    acc = RDPAccountant()
    for _ in range(30):
        acc.add(z)
    assert abs(acc.eps() - eps_for(z, 30)) < 1e-9
