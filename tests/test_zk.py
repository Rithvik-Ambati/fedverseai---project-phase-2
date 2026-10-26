import copy
import random
import time

import numpy as np
import pytest

from fedsec import zkproofs as zk
from fedsec.pedersen import get_group

G = get_group()
SCALE = 2 ** 20


def make(vec_norm, d=6, seed=0):
    rng = np.random.RandomState(seed)
    v = rng.normal(size=d)
    v = v / np.linalg.norm(v) * vec_norm
    return [int(round(x * SCALE)) for x in v]


def test_valid_proof_verifies_and_matches_commitment():
    clip = int(0.5 * SCALE)
    B = zk.bound_for(clip, 6)
    c = make(0.4)
    proof, Com_c, r = zk.prove(G, c, B, b"ctx", rng=random.Random(1))
    assert zk.verify(G, proof, Com_c, B, b"ctx")
    assert Com_c == G.commit(c, r)                      # the product of per-coordinate commitments IS the vector commitment


def test_norm_exactly_at_bound_and_zero_vector_verify():
    clip = int(0.5 * SCALE)
    B = zk.bound_for(clip, 6)
    for c in (make(0.5), [0] * 6):
        proof, Com_c, _ = zk.prove(G, c, B, b"x", rng=random.Random(2))
        assert zk.verify(G, proof, Com_c, B, b"x")


@pytest.mark.parametrize("norm", [0.6, 1.0, 5.0])
def test_oversized_vector_cannot_produce_a_valid_proof(norm):
    clip = int(0.5 * SCALE)
    B = zk.bound_for(clip, 6)
    c = make(norm)
    proof, Com_c, _ = zk.prove(G, c, B, b"ctx", rng=random.Random(3))
    assert not zk.verify(G, proof, Com_c, B, b"ctx")


def test_proof_is_bound_to_context_and_commitment():
    clip = int(0.5 * SCALE)
    B = zk.bound_for(clip, 6)
    c = make(0.3)
    proof, Com_c, _ = zk.prove(G, c, B, b"round1|client2", rng=random.Random(4))
    assert not zk.verify(G, proof, Com_c, B, b"round1|client3")           # replay for another client / round
    other, Com_o, _ = zk.prove(G, make(0.3, seed=9), B, b"round1|client2", rng=random.Random(5))
    assert not zk.verify(G, proof, Com_o, B, b"round1|client2")           # proof for a different commitment


def test_tampered_proofs_rejected():
    clip = int(0.5 * SCALE)
    B = zk.bound_for(clip, 6)
    proof, Com_c, _ = zk.prove(G, make(0.3), B, b"c", rng=random.Random(6))
    bad = copy.deepcopy(proof)
    e, zA, z1, z2, z3 = bad["conj"][0]
    bad["conj"][0] = (e, (zA + 1) % G.q, z1, z2, z3)
    assert not zk.verify(G, bad, Com_c, B, b"c")
    bad = copy.deepcopy(proof)
    e0, z0, e1, z1 = bad["or"][3]
    bad["or"][3] = (e0, (z0 + 1) % G.q, e1, z1)
    assert not zk.verify(G, bad, Com_c, B, b"c")
    bad = copy.deepcopy(proof)
    bad["Q"][1] = (bad["Q"][1] * G.g) % G.p                               # claim a different square
    assert not zk.verify(G, bad, Com_c, B, b"c")


def test_proof_hides_the_vector():
    # two different vectors with the same norm bound give proofs with different public values, and the verifier
    # only ever sees group elements and responses (sanity: the plaintext coordinates never appear)
    clip = int(0.5 * SCALE)
    B = zk.bound_for(clip, 6)
    c = make(0.3)
    proof, _, _ = zk.prove(G, c, B, b"c", rng=random.Random(7))
    flat = {str(x) for key in ("P", "A", "Q", "D") for x in proof[key]}
    assert not any(str(abs(ci)) in flat for ci in c if ci)


def test_cost_is_reasonable_for_small_models():
    clip = int(0.5 * SCALE)
    d = 14
    B = zk.bound_for(clip, d)
    c = make(0.4, d=d)
    t = time.time()
    proof, Com_c, _ = zk.prove(G, c, B, b"c", rng=random.Random(8))
    tp = time.time() - t
    t = time.time()
    assert zk.verify(G, proof, Com_c, B, b"c")
    tv = time.time() - t
    assert tp < 5 and tv < 5, (tp, tv)
