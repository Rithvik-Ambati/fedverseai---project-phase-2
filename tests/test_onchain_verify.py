"""The contract's 1024-bit modular multiplication and its on-chain check of the aggregate against commitments."""
import json
import os
import random
import shutil

import pytest

pytestmark = pytest.mark.skipif(shutil.which("npx") is None, reason="Node/npx not installed")

from fedsec import evmchain
from fedsec.federation import Config, Federation
from fedsec.pedersen import get_group

G = get_group()


@pytest.fixture(scope="module")
def bigtest():
    w3 = evmchain.get_w3()
    evmchain.load_artifact()
    path = os.path.join(evmchain.ROOT, "artifacts", "contracts", "Big.sol", "BigTest.json")
    art = json.load(open(path))
    c = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    rc = w3.eth.wait_for_transaction_receipt(c.constructor().transact({"from": w3.eth.accounts[0]}))
    return w3.eth.contract(address=rc["contractAddress"], abi=art["abi"])


def b128(x):
    return x.to_bytes(128, "big")


def test_modmul_matches_python_on_random_and_edge_values(bigtest):
    p = G.p
    rng = random.Random(1)
    cases = [(0, 0), (0, 5), (1, 1), (1, p - 1), (p - 1, p - 1), (p - 1, 2), (2 ** 1000, 2 ** 1000), (p - 2, p - 3)]
    cases += [(rng.randrange(p), rng.randrange(p)) for _ in range(40)]
    cases += [(G.g, G.h(3)), (G.h(1), G.h(1))]
    for a, b in cases:
        out = bigtest.functions.mul(b128(a), b128(b), b128(p)).call()
        assert int.from_bytes(out, "big") == (a * b) % p, (a, b)


def test_modmul_works_for_a_different_odd_modulus_too(bigtest):
    # p % 4 == 3 branch of the exact division by 4
    p = next(n for n in range(2 ** 1023 + 1, 2 ** 1023 + 5000, 2) if n % 4 == 3 and pow(2, n - 1, n) == 1)
    rng = random.Random(5)
    for _ in range(10):
        a, b = rng.randrange(p), rng.randrange(p)
        out = bigtest.functions.mul(b128(a), b128(b), b128(p)).call()
        assert int.from_bytes(out, "big") == (a * b) % p


def run(**kw):
    base = dict(rounds=3, n_clients=4, z=2.0, local_epochs=1, chain="evm", onchain_verify=True)
    base.update(kw)
    f = Federation(Config(**base))
    return f, f.run()


def test_contract_verifies_honest_aggregate_by_itself():
    f, res = run()
    ct = f.contract
    assert res["rejected_rounds"] == 0
    assert [ct.contract.functions.chainVerified(r).call() for r in range(3)] == [1, 1, 1]
    gas = [t["gas"] for t in ct.tx_log if t["method"] == "verifyAggregate"]
    assert gas and max(gas) < 4_000_000                                   # fits comfortably in one transaction


def test_contract_itself_rejects_swapped_aggregate_and_forged_input():
    for kw in (dict(server_attack="swap_aggregate"), dict(malicious={1: "forge"})):
        f, res = run(rounds=2, **kw)
        ct = f.contract
        assert res["rejected_rounds"] == 2, kw
        assert [ct.contract.functions.chainVerified(r).call() for r in range(2)] == [2, 2], kw
        assert "aggregate_verification_failed" in {e["type"] for e in res["events"]}


def test_lying_server_is_overridden_by_the_contract():
    """A malicious server tells the contract 'verified' for a tampered aggregate; the on-chain check wins."""
    cfg = Config(rounds=1, n_clients=4, z=2.0, local_epochs=1, chain="evm", onchain_verify=True,
                 server_attack="swap_aggregate")
    f = Federation(cfg)
    orig = f.contract.post_aggregate
    f.contract.post_aggregate = lambda r, s, m, a, verified, emergency=False, gate_ok=True: orig(r, s, m, a, True, emergency, gate_ok)
    res = f.run()
    assert f.contract.contract.functions.chainVerified(0).call() == 2
    assert res["rejected_rounds"] == 1
